// SPDX-License-Identifier: LGPL-3.0-or-later
//
// PcccGateway - Protocol Gateway for PCCC over DF1, CSPv4, and EIP
// Copyright (c) 2026 Ketut Kumajaya
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

using System.IO.Ports;
using System.Threading.Channels;
using PcccGateway.Common;
using PcccGateway.Interface;

namespace PcccGateway.Client;

/// <summary>
/// Serial port wrapper with robust byte array handling and deadlock prevention.
/// Supports dependency injection for testing via <see cref="ISerialPort"/>.
///
/// Threading model:
/// <list type="bullet">
///   <item>
///     One consumer task, started in the constructor and running until
///     <see cref="Dispose"/>. It is NEVER restarted on Open()/Close(), so
///     callbacks from two sessions can never overlap and arrival order is
///     preserved end to end.
///   </item>
///   <item>
///     Each received chunk is tagged with the session <c>generation</c> that was
///     active when it arrived. Open()/Close()/Dispose() bump the generation, so a
///     chunk still queued from a previous session is dropped by the consumer
///     rather than delivered late.
///   </item>
///   <item>
///     All lifecycle state (<c>_open</c>, <c>_closing</c>, <c>_disposed</c>,
///     <c>_generation</c>) is guarded by <c>_sync</c>. Operations are rejected
///     once disposal begins.
///   </item>
/// </list>
/// </summary>
public class SerialPortWrapper : ISerialPort
{
    private readonly ISerialPort _port;
    private readonly object _sync = new object();

    // Received chunks are handed off through this channel instead of being dispatched
    // straight from the SerialPort driver's own callback thread. Reading synchronously
    // there risks a deadlock if a handler calls back into the port (e.g. Close()) from
    // the same thread the driver uses to raise DataReceived. A single dedicated consumer
    // drains the channel and invokes BytesReceived in the exact order chunks arrived
    // — unlike a ThreadPool.QueueUserWorkItem-per-chunk approach, where the pool's own
    // scheduling gave no guarantee that two work items would run in the order they were
    // queued, letting a later chunk of the same DF1/CSP stream reach the consumer before
    // an earlier one and corrupt frame reassembly.
    //
    // Unbounded, and one channel rather than two. An earlier revision bounded this at
    // 100 and closed the port on overflow, and fed a second channel so a slow
    // subscriber could not stall the reader. Both existed for a subscriber that ran
    // user code on this consumer. DF1BaseTransport now owns a callback executor and
    // raises its public events there, so the handler here only parses into a ring
    // buffer and returns — bounded work, no user code. What the bound bought is gone;
    // what it cost was a failure mode of its own, dropping the link because a handler
    // was briefly slow.
    private readonly Channel<(int gen, byte[] data)> _rxChannel =
        Channel.CreateUnbounded<(int, byte[])>(new UnboundedChannelOptions
        {
            SingleReader = true,   // only CallbackLoopAsync reads
            SingleWriter = false   // the driver may raise DataReceived on any pool thread
        });

    private readonly Task _callbackTask;

    // Guarded by _sync.
    private int _generation;             // bumped on every Open/Close/Dispose transition
    private bool _open;                  // is the underlying port open for this generation
    private bool _disposed;
    // Set the moment Dispose() commits, BEFORE it waits for the callback lease.
    // WaitForCallbackLease() parks in Monitor.Wait, which releases _sync — so
    // without this marker a second Dispose() would pass the _disposed check and
    // repeat the whole teardown, and Open()/Read()/Write() could still start
    // work after disposal had begun.
    private bool _disposing;

    // True while a Close() has claimed the teardown but has not finished it.
    // WaitForCallbackLease() releases _sync, and the teardown is only half done at
    // that point: _open is already false but the generation has not been bumped.
    // Without this marker Open() would see _open == false, publish a whole new
    // session, and the parked close would then wake up, bump the generation and
    // shut the port belonging to that NEW session.
    private bool _closing;

    // Managed thread id currently executing a BytesReceived handler, or -1.
    // Lets Dispose()/Close() detect when they are being called from within a
    // callback and skip synchronously waiting on the callback task/lease (which
    // would wait on their own thread). Written with Volatile so callers see it.
    private int _callbackThreadId = -1;

    // Callback lease: true between the moment the consumer passes the generation
    // check (admitting a chunk for delivery) and the moment its handler returns.
    // Close()/Dispose() wait for the lease to clear before bumping the generation.
    //
    // The generation tag alone is not enough. It stops a chunk being admitted into
    // the wrong session, but says nothing about one already being delivered: without
    // the lease, Close() would return while a handler was still running, Open()
    // would clear the transport's receive buffer, and that handler would then finish
    // writing the previous session's bytes into the fresh one.
    // Guarded by _sync (+ Monitor pulse on release).
    private bool _callbackActive;

    /// <summary>
    /// Raised, in strict arrival order, for each received chunk on the single
    /// lifetime callback consumer.
    /// </summary>
    /// <remarks>
    /// KNOWN LIMITATION — re-entrancy: handlers run on the one consumer thread,
    /// which is also the only thread that parses inbound bytes. A handler that
    /// BLOCKS waiting for more of those bytes deadlocks, because what it waits for
    /// can only be parsed once it returns. Handlers must be non-blocking; offload
    /// anything that waits on further I/O to another thread.
    ///
    /// The DF1 transports can no longer hit this. Their handler here only parses
    /// and queues, and their own public events are raised on DF1BaseTransport's
    /// callback executor — so a subscriber calling <c>SendFrame()</c> and waiting
    /// for an ACK is not standing on this consumer. The limitation still binds any
    /// other direct subscriber.
    /// </remarks>
    public event EventHandler<byte[]>? BytesReceived;

    public int BaudRate => _port.BaudRate;
    public Parity Parity => _port.Parity;

    /// <summary>
    /// Initializes a new instance of the <see cref="SerialPortWrapper"/> class
    /// with a real serial port.
    /// </summary>
    public SerialPortWrapper(string portName, int baudRate, Parity parity)
        : this(new SystemSerialPort(portName, baudRate, parity))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SerialPortWrapper"/> class
    /// with a custom <see cref="ISerialPort"/> (for testing).
    /// </summary>
    public SerialPortWrapper(ISerialPort port)
    {
        _port = port ?? throw new ArgumentNullException(nameof(port));
        _port.BytesReceived += OnBytesReceived;

        // One consumer for the lifetime of the wrapper. It runs until Dispose()
        // completes the channel.
        _callbackTask = Task.Run(CallbackLoopAsync);
    }

    private void OnBytesReceived(object? sender, byte[] chunk)
    {
        if (chunk == null || chunk.Length == 0) return;

        int gen;
        lock (_sync)
        {
            if (_disposed || !_open) return;   // ignore chunks outside an open session
            gen = _generation;
        }

        // Take ownership of the bytes before deferring them onto the channel: the
        // producing ISerialPort is only required to keep the buffer valid for the
        // duration of its synchronous BytesReceived call, and an injected/test
        // implementation may reuse or mutate the same array afterwards. Cloning
        // guarantees the deferred consumer parses a stable snapshot.
        byte[] ownedChunk = (byte[])chunk.Clone();

        // Never blocks and only fails once the channel is completed at shutdown,
        // so the driver's callback thread is not held up.
        _rxChannel.Writer.TryWrite((gen, ownedChunk));
    }

    /// <summary>
    /// Invokes <see cref="BytesReceived"/> for each chunk strictly in arrival
    /// order. This is the ONLY consumer, so handlers from different sessions can
    /// never run concurrently. A chunk whose tagged generation no longer matches
    /// the active session is dropped rather than delivered late.
    /// </summary>
    private async Task CallbackLoopAsync()
    {
        try
        {
            await foreach (var item in _rxChannel.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                bool deliver;
                lock (_sync)
                {
                    deliver = !_disposed && _open && item.gen == _generation;
                    // Acquire the lease in the SAME critical section as the check,
                    // so a concurrent Close() either bumps the generation before
                    // this check (chunk dropped) or waits for the lease below
                    // before doing so (chunk delivered to its own session).
                    if (deliver) _callbackActive = true;
                }
                if (!deliver) continue;

                Volatile.Write(ref _callbackThreadId, Environment.CurrentManagedThreadId);
                try
                {
                    BytesReceived?.Invoke(this, item.data);
                }
                catch
                {
                    // Ignore exceptions in event handlers (upper layer handles)
                }
                finally
                {
                    Volatile.Write(ref _callbackThreadId, -1);
                    lock (_sync)
                    {
                        _callbackActive = false;
                        Monitor.PulseAll(_sync);
                    }
                }
            }
        }
        catch (ChannelClosedException)
        {
            // Channel closed during disposal.
        }
    }

    public void Open()
    {
        lock (_sync)
        {
            if (_disposed || _disposing)
                throw new ObjectDisposedException(nameof(SerialPortWrapper));

            // Let any half-finished teardown complete first — see _closing. Skipped
            // on the callback thread: a handler calling Open() while a teardown is
            // parked waiting for that same handler's lease would deadlock.
            if (Volatile.Read(ref _callbackThreadId) != Environment.CurrentManagedThreadId)
            {
                while (_closing)
                    Monitor.Wait(_sync);

                // Disposal can be claimed while we were parked.
                if (_disposed || _disposing)
                    throw new ObjectDisposedException(nameof(SerialPortWrapper));
            }

            if (_open)
                return;

            _port.Open();

            // New session: bump the generation so any chunk still queued from a
            // previous session is dropped by the consumer.
            _generation++;
            _open = true;
        }
    }

    /// <inheritdoc/>
    public void Close()
    {
        lock (_sync)
        {
            if (!_open)
                return;

            // Close the session for new work FIRST. WaitForCallbackLease() parks
            // in Monitor.Wait, which releases _sync; leaving _open true across
            // that gap would let a Write()/Read() proceed against a session that
            // is already going away.
            _open = false;

            // Claim the teardown for the rest of this method, so no Open() can
            // publish a new session while we are parked below.
            _closing = true;
            try
            {
                // Wait for any callback already admitted for delivery to finish
                // before invalidating the session. Skipped when we are ON the
                // callback thread (a handler calling Close()) — that would
                // self-deadlock.
                WaitForCallbackLease();

                // Invalidate the just-ended session so any chunk still in flight is
                // dropped by the consumer instead of delivered after Close().
                _generation++;

                // Never swallowed: a failing Close() can leave the OS handle open
                // while this wrapper reports closed, and the next Close() returns
                // immediately because _open is already false. Dispose() captures
                // and rethrows its teardown error, so at minimum make this visible.
                try { if (_port.IsOpen) _port.Close(); }
                catch (Exception ex)
                {
                    Logger.Warn(this, $"SerialPortWrapper: underlying port Close() failed - {ex.GetType().Name}: {ex.Message}");
                }
            }
            finally
            {
                _closing = false;
                Monitor.PulseAll(_sync);   // wake any Open() waiting this out
            }
        }
    }

    /// <summary>
    /// Waits (holding <c>_sync</c>) until no callback lease is active. Returns
    /// immediately when called from the callback thread itself.
    /// </summary>
    private void WaitForCallbackLease()
    {
        if (Volatile.Read(ref _callbackThreadId) == Environment.CurrentManagedThreadId)
            return;   // called from within the handler — cannot wait on ourselves
        while (_callbackActive)
            Monitor.Wait(_sync);
    }

    public void Write(byte[] buffer, int offset, int count)
    {
        lock (_sync)
        {
            if (_disposed || _disposing)
                throw new ObjectDisposedException(nameof(SerialPortWrapper));

            if (!_open || !_port.IsOpen)
                throw new InvalidOperationException("Serial port is closed.");

            _port.Write(buffer, offset, count);
        }
    }

    public bool IsOpen
    {
        get { lock (_sync) { return _open && !_disposed && _port.IsOpen; } }
    }

    public bool RtsEnable
    {
        get { lock (_sync) { return _port.RtsEnable; } }
        set
        {
            lock (_sync)
            {
                if (_disposed || _disposing)
                    throw new ObjectDisposedException(nameof(SerialPortWrapper));
                _port.RtsEnable = value;
            }
        }
    }

    public bool DtrEnable
    {
        get { lock (_sync) { return _port.DtrEnable; } }
        set
        {
            lock (_sync)
            {
                if (_disposed || _disposing)
                    throw new ObjectDisposedException(nameof(SerialPortWrapper));
                _port.DtrEnable = value;
            }
        }
    }

    public void Dispose()
    {
        Exception? disposeError = null;

        // Coordinate teardown with _sync so a concurrent Open/Close/I/O cannot
        // start work on disposed resources or after channel completion.
        lock (_sync)
        {
            if (_disposed || _disposing) return;

            // Reserve disposal BEFORE waiting — see _disposing.
            _disposing = true;
            _open = false;

            // Wait for any admitted callback to finish (unless we ARE that
            // callback) before invalidating the session.
            WaitForCallbackLease();

            _disposed = true;
            _generation++;

            // Unsubscribe first to prevent new chunks from arriving.
            _port.BytesReceived -= OnBytesReceived;

            // Complete the channel even if the port teardown throws, so the
            // consumer is guaranteed to terminate. Capture the error and rethrow
            // it only after the coordinated teardown below.
            try
            {
                try { _port.Close(); } catch { }
                _port.Dispose();
            }
            catch (Exception ex)
            {
                disposeError = ex;
            }
            finally
            {
                _rxChannel.Writer.TryComplete();
            }
        }

        // If Dispose() is being called from inside a BytesReceived handler, we are
        // ALREADY executing on _callbackTask — waiting on it would block until the
        // handler returns (i.e. always hit the timeout) and cannot achieve
        // coordinated termination. Skip the synchronous wait in that case; the
        // consumer terminates on its own once the completed channel drains.
        bool onCallbackThread = Volatile.Read(ref _callbackThreadId) == Environment.CurrentManagedThreadId;

        if (!onCallbackThread)
        {
            // Wait for the consumer OUTSIDE _sync: it takes _sync for its
            // generation check, so holding it here would deadlock.
            try
            {
                _callbackTask.Wait(2000);
            }
            catch (AggregateException) { }
        }

        if (disposeError != null)
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(disposeError).Throw();
    }

    /// <summary>
    /// Wraps a real <see cref="SerialPort"/> to implement <see cref="ISerialPort"/>.
    /// </summary>
    private sealed class SystemSerialPort : ISerialPort
    {
        private readonly SerialPort _port;

        /// <summary>
        /// Upper bound on chunks read per DataReceived callback. A continuously
        /// busy line would otherwise keep the condition true indefinitely and hold
        /// the driver's callback thread inside this handler. Whatever is left stays
        /// in the driver buffer and is picked up by the next DataReceived, which
        /// the driver raises while bytes remain.
        /// </summary>
        private const int MaxChunksPerCallback = 16;

        public event EventHandler<byte[]>? BytesReceived;

        public bool IsOpen => _port.IsOpen;
        public int BaudRate => _port.BaudRate;
        public Parity Parity => _port.Parity;

        public bool RtsEnable
        {
            get => _port.RtsEnable;
            set => _port.RtsEnable = value;
        }

        public bool DtrEnable
        {
            get => _port.DtrEnable;
            set => _port.DtrEnable = value;
        }

        public SystemSerialPort(string portName, int baudRate, Parity parity)
        {
            _port = new SerialPort(portName, baudRate, parity, 8, StopBits.One)
            {
                ReadTimeout = 2000,
                WriteTimeout = 2000
            };
            _port.DataReceived += (s, e) =>
            {
                try
                {
                    int chunks = 0;
                    while (_port.IsOpen && _port.BytesToRead > 0 && chunks++ < MaxChunksPerCallback)
                    {
                        int toRead = _port.BytesToRead;
                        byte[] buffer = new byte[toRead];
                        int read = _port.Read(buffer, 0, toRead);
                        if (read <= 0) break;

                        byte[] actualData = new byte[read];
                        Buffer.BlockCopy(buffer, 0, actualData, 0, read);
                        BytesReceived?.Invoke(this, actualData);
                    }
                }
                catch
                {
                    // Ignore serial port read errors; upper layer will timeout
                }
            };
        }

        public void Open() => _port.Open();
        public void Close() => _port.Close();
        public void Write(byte[] buffer, int offset, int count) => _port.Write(buffer, offset, count);
        public void Dispose() => _port.Dispose();
    }
}
