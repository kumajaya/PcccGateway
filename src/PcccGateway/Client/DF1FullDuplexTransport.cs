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
using PcccGateway.Interface;
using PcccGateway.Common;

namespace PcccGateway.Client;

/// <inheritdoc cref="ITransport"/>
/// <summary>
/// DF1 full‑duplex transport over RS‑232 (point‑to‑point master).
/// Handles DLE stuffing, CRC‑16/BCC, ACK/NAK, ENQ, and automatic backoff.
/// Reference: Allen Bradley Publication 1770-6.5.16, Chapters 5-7.
/// </summary>
/// <remarks>
/// Re-entrancy: <see cref="ITransport.FrameReceived"/> and
/// <see cref="ITransport.RawFrameReceived"/> handlers MAY call
/// <see cref="SendFrame"/> synchronously. Both are posted to the callback
/// executor DF1BaseTransport owns, which is a different thread from the one that
/// parses inbound bytes — so a handler waiting for an ACK no longer starves the
/// parsing that ACK depends on.
///
/// (Before that executor existed, both were raised inline on the serial callback
/// thread and such a send failed with a TimeoutException every time, even when
/// the peer answered immediately. DF1CallbackReentrancyTests covers it.)
///
/// One limit remains: the executor is single-threaded, so a handler that blocks
/// delays every LATER callback. Arrival order is preserved, latency is not.
/// </remarks>
public class DF1FullDuplexTransport : DF1BaseTransport
{
    // --- State for receive frame assembly ---
    private readonly object _rxLock = new object();
    // Serialises SendFrame so concurrent callers (e.g. multiple EIP clients
    // multiplexed through the gateway) cannot interleave their DLE STX..DLE ETX
    // byte streams on the wire or race on the shared ACK/NAK signalling state.
    private readonly object _txLock = new object();
    // Serialises the whole Open()/Close()/Dispose() lifecycle transition so a
    // concurrent Open() cannot clear _closing in the middle of a Close() that is
    // still tearing the port down (which would let later sends run against a
    // closed port). Always taken as the OUTERMOST lock in those three methods.
    private readonly object _lifecycleLock = new object();
    private readonly RingBuffer _rxBuffer;
    private DateTime _frameStartTime = DateTime.MinValue;
    private const int FrameTimeoutMs = 500;      // Max time between DLE STX and DLE ETX
    private const int MaxBufferBytes = 4096;     // Safety limit

    // --- ACK/NAK signalling ---
    // A FRESH waiter per attempt, published under _rxLock. The receive thread
    // captures whichever waiter is current at the moment it parses the ACK/NAK
    // and signals THAT one, after the queued control replies have gone out.
    //
    // A single shared event cannot do this safely. The flag is set inside
    // _rxLock but the signal is deliberately deferred until after the control
    // flush, and in that gap a Wait() can time out, observe the flag, and
    // return success. The next attempt would then Reset() the shared event just
    // before the deferred Set() ran — and that stale signal would wake the NEW
    // transaction, which finds no flags set and fails with a spurious timeout.
    // With a per-attempt waiter, a late signal lands on an object nobody awaits.
    private ManualResetEventSlim? _currentWaiter;   // guarded by _rxLock
    private volatile bool _ackReceived;
    private volatile bool _nakReceived;

    // Set by Close() so a SendFrame currently blocked on its waiter knows the
    // wake-up is a shutdown, not an ACK/NAK, and exits promptly instead of waiting out the
    // full timeout. Without this, stopping the driver while a frame was awaiting ACK (e.g.
    // the processor-family diagnostic probe against an unresponsive PLC) would hang for the
    // whole response timeout. Guarded by _lifecycleLock for lifecycle transitions.
    private volatile bool _closing;

    /// <summary>
    /// Signals a waiter captured earlier by the receive thread, tolerating it
    /// having been disposed by its owner in the meantime.
    /// </summary>
    private static void SignalWaiter(ManualResetEventSlim? waiter)
    {
        try { waiter?.Set(); } catch (ObjectDisposedException) { }
    }

    // --- ENQ signalling (SendEnqAndWaitForAck shares _currentWaiter) ---
    private volatile bool _ackFlagForEnq;
    private volatile bool _nakFlagForEnq;

    // The last link-layer reply WE sent for an inbound data frame: ACK when it
    // validated, NAK when it did not. This is what an incoming ENQ asks us to
    // repeat, so only inbound-frame validation may change it.
    //
    // Renamed from _lastResponseWasNAK, whose "response" was ambiguous between
    // the reply we sent and the reply we received — an ambiguity the code had
    // already fallen into (see the ctrl == NAK branch in OnBytesReceived).
    private bool _lastReplyWasNak = false;

    /// <summary>
    /// Initialises the DF1 full‑duplex transport with a custom <see cref="ISerialPort"/>.
    /// </summary>
    public DF1FullDuplexTransport(ISerialPort port) : base(port)
    {
        _rxBuffer = new RingBuffer(MaxBufferBytes);
        _port.BytesReceived += OnBytesReceived;
    }

    /// <summary>
    /// Initialises the DF1 full‑duplex transport with standard serial port parameters.
    /// </summary>
    public DF1FullDuplexTransport(string portName, int baudRate, Parity parity)
        : base(portName, baudRate, parity)
    {
        _rxBuffer = new RingBuffer(MaxBufferBytes);
        _port.BytesReceived += OnBytesReceived;
    }

    /// <inheritdoc/>
    public override void SendFrame(byte[] innerFrame)
    {
        if (innerFrame == null || innerFrame.Length == 0)
            throw new ArgumentException("Inner frame cannot be null or empty.", nameof(innerFrame));

        // The raw-frame diagnostics are deferred until after _txLock is released:
        // a subscriber that blocks on another thread which itself calls SendFrame()
        // or Close() would otherwise deadlock on _txLock. Each frame is recorded
        // only AFTER it actually reaches the wire, and every write attempt (retry)
        // is reported separately — so the event never announces a frame that was
        // never written, nor collapses retries into a single notification.
        List<byte[]>? writtenFrames = null;
        try
        {
            // One transaction at a time: prevents interleaved wire writes and
            // races on _ackReceived/_nakReceived/_currentWaiter when multiple clients
            // forward through the gateway concurrently.
            lock (_txLock)
            {
                // Build the complete wire frame using base helper
                byte[] frame = BuildWireFrame(innerFrame);

                // Send with retry (max 2 attempts)
                int retries = 0;
                const int maxRetries = 2;

                // Timeout in ms derived from MaxTicks (each tick was 20 ms in the old loop).
                int timeoutMs = MaxTicks * 20;

                while (retries < maxRetries)
                {
                    // Bail out before touching the event or port if a close has begun.
                    if (_closing)
                        throw new TimeoutException("Send aborted: transport is closing.");

                    var waiter = new ManualResetEventSlim(false);
                    try
                    {
                        // Publish the waiter with the flags it owns, so the receive
                        // thread can only ever capture a consistent pair.
                        lock (_rxLock)
                        {
                            _ackReceived = false;
                            _nakReceived = false;
                            _currentWaiter = waiter;
                        }

                        // Recheck AFTER publishing: Close() may have signalled the
                        // previous waiter between the _closing check above and here.
                        if (_closing)
                            throw new TimeoutException("Send aborted: transport is closing.");

                        // SleepDelay is applied before writing (not after receiving ACK).
                        // An earlier revision slept inside the receive-thread lock after ACK — that
                        // blocked the serial port reader. Sleeping here on the send thread is equivalent
                        // for flow control purposes and does not block incoming bytes.
                        if (SleepDelay > 0)
                            Thread.Sleep(SleepDelay);

                        WritePort(frame, 0, frame.Length);
                        // Record only after the write actually succeeded.
                        (writtenFrames ??= new List<byte[]>()).Add(frame);

                        // Wait for ACK or NAK — wakes immediately when the receive thread
                        // signals this waiter, or when Close() aborts a shutdown-in-progress.
                        waiter.Wait(timeoutMs);
                    }
                    catch (ObjectDisposedException)
                    {
                        // The port was disposed mid-cycle. That only happens on shutdown,
                        // so surface it as an aborted send rather than an unexpected type.
                        throw new TimeoutException("Send aborted: transport is closing.");
                    }
                    catch (InvalidOperationException) when (_closing)
                    {
                        // WritePort refused because teardown had begun.
                        throw new TimeoutException("Send aborted: transport is closing.");
                    }
                    finally
                    {
                        // Retire the waiter before disposing it, so the receive thread
                        // cannot pick it up again. One that was already captured is
                        // signalled through SignalWaiter, which tolerates disposal.
                        lock (_rxLock)
                        {
                            if (ReferenceEquals(_currentWaiter, waiter))
                                _currentWaiter = null;
                        }
                        waiter.Dispose();
                    }

                    // Shutdown requested while waiting: abandon the send instead of retrying or
                    // waiting out the timeout. Surfaces as a normal send failure to the caller.
                    if (_closing)
                        throw new TimeoutException("Send aborted: transport is closing.");

                    if (_ackReceived)
                        return;                     // Success

                    if (_nakReceived)
                    {
                        // Backoff: increase sleep delay for the next retry
                        if (SleepDelay < 400) SleepDelay += 50;
                        retries++;
                        continue;
                    }

                    // Timeout – no ACK/NAK received
                    throw new TimeoutException("No ACK or NAK received within the specified timeout.");
                }

                throw new TimeoutException($"Failed to send frame after {maxRetries} retries.");
            } // _txLock
        }
        finally
        {
            // Raise the diagnostic events outside _txLock, whether the send
            // succeeded or threw, so subscribers can safely call back in. One
            // event per actual write attempt, in the order they went on the wire.
            //
            // Deliberately NOT protected by a generation-aware callback lease,
            // though a concurrent Close() can finish first. A lease does not remove
            // that race, it relocates it: teardown would then block for as long as
            // a subscriber's handler runs. See the matching note in
            // DF1HalfDuplexTransport.SendFrame for the full reasoning.
            if (writtenFrames != null)
            {
                foreach (byte[] f in writtenFrames)
                    OnRawFrameSent(f);
            }
        }
    }

    /// <summary>
    /// Sends a standalone ENQ (DLE 0x05) and waits for an ACK or NAK response.
    /// Used by the auto‑detect routine to test communication settings.
    /// </summary>
    /// <returns>0 if ACK received, -2 if NAK received, -3 if timeout.</returns>
    public int SendEnqAndWaitForAck()
    {
        if (!IsOpen)
            Open();

        // Serialise with SendFrame: an ENQ probe (auto-detect) must not interleave
        // its bytes or share the ACK/NAK signalling state with an in-flight send.
        lock (_txLock)
        {
            if (_closing || !IsOpen)
                return -3;

            var waiter = new ManualResetEventSlim(false);
            try
            {
                lock (_rxLock)
                {
                    _ackFlagForEnq = false;
                    _nakFlagForEnq = false;
                    _currentWaiter = waiter;
                }

                // Recheck AFTER publishing: Close() may have signalled the previous
                // waiter between the check above and here.
                if (_closing)
                    return -3;

                SendControl(ENQ);

                int timeoutMs = MaxTicks * 20;
                waiter.Wait(timeoutMs);

                if (_closing)
                    return -3;
                if (_ackFlagForEnq) return 0;
                if (_nakFlagForEnq) return -2;
                return -3;
            }
            finally
            {
                lock (_rxLock)
                {
                    if (ReferenceEquals(_currentWaiter, waiter))
                        _currentWaiter = null;
                }
                waiter.Dispose();
            }
        }
    }

    /// <summary>
    /// Resets the ACK/NAK flags used by <see cref="SendEnqAndWaitForAck"/>.
    /// </summary>
    public void ResetAckNakFlags()
    {
        _ackFlagForEnq = false;
        _nakFlagForEnq = false;
    }

    // --- Serial receive handler (state machine) ---
    private void OnBytesReceived(object? sender, byte[] chunk)
    {
        if (chunk == null || chunk.Length == 0) return;

        // A single chunk from the serial wrapper can contain several complete
        // frames (it reads all available bytes at once), so decoded PDUs are
        // collected in a list — one slot would drop all but the last frame.
        List<byte[]>? pdusToDeliver = null;
        // Every link-control response (ACK/NAK for a data frame, or the ENQ
        // status reply) is queued here IN PARSE ORDER and flushed to the wire —
        // in that order — after _rxLock is released. This keeps the on-wire order
        // correct when a chunk mixes ENQ and data frames (an ENQ parsed first is
        // answered first), preserves one reply per ENQ, and stops us writing to
        // the port while holding _rxLock.
        List<byte>? controlToSend = null;
        // Waking the sender is deferred until AFTER controlToSend has been flushed.
        // Signalling during parsing would let the awakened sender start its next
        // write ahead of an ACK/NAK still queued for an earlier inbound frame,
        // breaking the on-wire ordering the queue exists to guarantee.
        //
        // The waiter is captured while parsing rather than re-read after the
        // flush: by then its transaction may already have completed and a
        // successor published its own waiter, which our signal must not touch.
        ManualResetEventSlim? waiterToSignal = null;
        // Raw-frame diagnostics are accumulated and raised after _rxLock is
        // released: a subscriber that re-enters SendFrame()/Close()/Open() from
        // OnRawFrameReceived would otherwise deadlock through _rxLock beneath
        // _txLock/_lifecycleLock.
        List<byte[]>? rawFramesToRaise = null;

        lock (_rxLock)
        {
            // Check capacity BEFORE adding: RingBuffer's own capacity equals
            // MaxBufferBytes exactly, so AddRange throws InvalidOperationException
            // the instant the combined size would exceed it — the buffer's Count
            // can never actually be observed to exceed MaxBufferBytes afterwards.
            // A prior version checked Count > MaxBufferBytes only after calling
            // AddRange, which meant this safety path could never be reached; an
            // oversized burst (e.g. line noise with no recognisable frame) would
            // instead throw out of this method entirely, silently discarding
            // whatever had been buffered with no recovery or log trace.
            if (chunk.Length + _rxBuffer.Count > MaxBufferBytes)
            {
                // Logged because clearing discards buffered bytes mid-frame, and the only
                // symptom downstream is a frame that never completes or fails its checksum
                // — a cause nobody can infer from that alone.
                Logger.Warn(this, $"{GetType().Name}: receive buffer would overflow " +
                                  $"({_rxBuffer.Count} buffered + {chunk.Length} incoming > {MaxBufferBytes} max) " +
                                  "- discarding the partial frame and resynchronising");
                _rxBuffer.Clear();
                _frameStartTime = DateTime.MinValue;
                if (chunk.Length > MaxBufferBytes)
                    return;
            }
            _rxBuffer.AddRange(chunk, 0, chunk.Length);

            bool consumed = true;
            while (consumed)
            {
                consumed = false;
                if (_rxBuffer.Count < 2) break;

                // Synchronisation: find a DLE byte
                if (_rxBuffer[0] != DLE)
                {
                    _rxBuffer.Advance(1);
                    consumed = true;
                    continue;
                }

                byte ctrl = _rxBuffer[1];

                // --- 2‑byte link control: ACK, NAK, ENQ ---
                if (ctrl == ACK || ctrl == NAK || ctrl == ENQ)
                {
                    _rxBuffer.Advance(2);
                    _frameStartTime = DateTime.MinValue;

                    if (ctrl == ACK)
                    {
                        // Set the flags now; the actual wake-up is deferred until
                        // after the queued control replies have gone out, so the
                        // sender cannot write ahead of them. SendFrame reads these
                        // flags only after its Wait() returns.
                        _ackReceived = true;
                        _ackFlagForEnq = true;
                        waiterToSignal = _currentWaiter;
                    }
                    else if (ctrl == NAK)
                    {
                        _nakReceived = true;
                        _nakFlagForEnq = true;
                        // Deliberately does NOT touch _lastReplyWasNak: this NAK is
                        // the peer rejecting OUR outbound frame, which says nothing
                        // about whether we accepted THEIR last data frame. Setting it
                        // here made a later ENQ answer NAK for an unrelated reason,
                        // prompting the peer to retransmit a frame we already had.
                        waiterToSignal = _currentWaiter;
                    }
                    else if (ctrl == ENQ)
                    {
                        // Reply to ENQ with the status of the last received frame,
                        // captured at THIS parse position (AB Pub 1770-6.5.16).
                        // Queue one reply per ENQ.
                        (controlToSend ??= new List<byte>()).Add(_lastReplyWasNak ? NAK : ACK);
                    }
                    consumed = true;
                    continue;
                }

                // --- Data frame: DLE STX ... DLE ETX ---
                if (ctrl == STX)
                {
                    if (_frameStartTime == DateTime.MinValue)
                        _frameStartTime = DateTime.UtcNow;

                    // Frame timeout check (prevents hanging on partial frames)
                    if ((DateTime.UtcNow - _frameStartTime).TotalMilliseconds > FrameTimeoutMs)
                    {
                        _rxBuffer.Advance(2);
                        _frameStartTime = DateTime.MinValue;
                        consumed = true;
                        continue;
                    }

                    // Find DLE ETX, skipping over stuffed DLE pairs (0x10 0x10)
                    int etxIndex = -1;
                    for (int i = 2; i < _rxBuffer.Count - 1; i++)
                    {
                        if (_rxBuffer[i] == DLE)
                        {
                            if (_rxBuffer[i + 1] == DLE)
                            {
                                i++; // skip the stuffed pair
                                continue;
                            }
                            if (_rxBuffer[i + 1] == ETX)
                            {
                                etxIndex = i;
                                break;
                            }
                        }
                    }
                    if (etxIndex == -1)
                        break; // need more bytes

                    int csLen = (ChecksumType == CheckSumOptions.Crc) ? 2 : 1;
                    int totalFrameLen = etxIndex + 2 + csLen;
                    if (_rxBuffer.Count < totalFrameLen)
                        break; // checksum bytes not yet fully received

                    // Extract the complete frame using ArrayPool to reduce allocations
                    byte[] frame = System.Buffers.ArrayPool<byte>.Shared.Rent(totalFrameLen);
                    try
                    {
                        Array.Clear(frame, 0, totalFrameLen);
                        _rxBuffer.Peek(frame, 0, totalFrameLen);
                        // Create a copy for the RawFrameReceived event (since we must not pass the rented buffer out)
                        byte[] rawFrameCopy = new byte[totalFrameLen];
                        Array.Copy(frame, 0, rawFrameCopy, 0, totalFrameLen);
                        (rawFramesToRaise ??= new List<byte[]>()).Add(rawFrameCopy);
                        _rxBuffer.Advance(totalFrameLen);
                        _frameStartTime = DateTime.MinValue;

                        // Unstuff the payload between DLE STX and DLE ETX
                        int payloadLen = etxIndex - 2;
                        byte[] stuffedPayload = new byte[payloadLen];
                        Array.Copy(frame, 2, stuffedPayload, 0, payloadLen);
                        byte[] innerFrame = RemoveDleStuffing(stuffedPayload);

                        // Validate checksum
                        bool valid;
                        if (ChecksumType == CheckSumOptions.Crc)
                        {
                            ushort calc = CalculateChecksum(innerFrame, CheckSumOptions.Crc);
                            ushort recv = (ushort)(frame[etxIndex + 2] | (frame[etxIndex + 3] << 8));
                            valid = calc == recv;
                        }
                        else // BCC
                        {
                            byte calc = (byte)CalculateChecksum(innerFrame, CheckSumOptions.Bcc);
                            byte recv = frame[etxIndex + 2];
                            valid = calc == recv;
                        }

                        // Queue ACK or NAK at this parse position (flushed in order
                        // after the lock, so we never write to the port under _rxLock).
                        if (valid)
                        {
                            (controlToSend ??= new List<byte>()).Add(ACK);
                            _lastReplyWasNak = false;
                            (pdusToDeliver ??= new List<byte[]>()).Add(innerFrame);
                        }
                        else
                        {
                            (controlToSend ??= new List<byte>()).Add(NAK);
                            _lastReplyWasNak = true;
                            if (SleepDelay < 400) SleepDelay += 50;
                        }
                    }
                    finally
                    {
                        System.Buffers.ArrayPool<byte>.Shared.Return(frame);
                    }
                    consumed = true;
                    continue;
                }

                // DLE followed by an unexpected byte – discard the DLE and resync
                _rxBuffer.Advance(1);
                consumed = true;
            }
        }

        // Flush all queued link-control responses to the wire FIRST, in parse
        // order, so ACK/NAK/ENQ replies leave in the exact sequence the peer's
        // bytes arrived. Done outside _rxLock so a blocking write cannot stall
        // the receive thread.
        if (controlToSend != null)
        {
            foreach (byte c in controlToSend)
                SendControl(c);
        }

        // Only now wake a waiting SendFrame / ENQ probe: every control reply owed
        // for this chunk is already on the wire, so the sender's next write cannot
        // jump ahead of them. Done before the callbacks so a slow diagnostic
        // subscriber does not add latency to the ACK/NAK wait.
        SignalWaiter(waiterToSignal);

        // Then raise diagnostic/data callbacks (raw before decoded) outside the
        // lock, so subscriber callbacks cannot re-enter under _rxLock.
        // Posted, not invoked: this is the serial callback thread, and a handler
        // that calls back into the transport here would starve the parsing its
        // own ACK depends on. Both kinds share one queue, so raw still precedes
        // decoded for the same frame.
        if (rawFramesToRaise != null)
        {
            foreach (byte[] rawFrame in rawFramesToRaise)
                PostRawFrameReceived(rawFrame);
        }
        if (pdusToDeliver != null)
        {
            foreach (byte[] pdu in pdusToDeliver)
                PostFrameReceived(pdu);
        }
    }

    /// <inheritdoc/>
    public override void Open()
    {
        // Serialise the whole transition with Close()/Dispose() so a concurrent
        // Close() cannot interleave and leave the port closed with _closing == false.
        lock (_lifecycleLock)
        {
            lock (_txLock)
            {
                // Reset all waiter/transaction state so a partial frame or stale
                // ACK/NAK flag left by the previous session cannot corrupt or
                // reject the first frame after reopening.
                _ackReceived = false;
                _nakReceived = false;
                _ackFlagForEnq = false;
                _nakFlagForEnq = false;
                _lastReplyWasNak = false;

                lock (_rxLock)
                {
                    _currentWaiter = null;
                    _rxBuffer.Clear();
                    _frameStartTime = DateTime.MinValue;
                }

                // Clear _closing only AFTER the port opens successfully. If
                // base.Open() throws, the transport must stay in the closed
                // state so later sends observe the failed lifecycle rather than
                // writing to a port that never opened.
                try
                {
                    base.Open();
                    _closing = false;
                }
                catch
                {
                    _closing = true;
                    throw;
                }
            }
        }
    }

    /// <inheritdoc/>
    public override void Close()
    {
        lock (_lifecycleLock)
        {
            // Signal shutdown and wake any SendFrame blocked on the ACK/NAK wait BEFORE
            // closing the port, so a send in progress against an unresponsive PLC returns
            // immediately instead of waiting out its timeout.
            //
            // A SendFrame that reaches its Wait() just AFTER this point is covered by a
            // different mechanism, not by this signal: its waiter is created fresh and was
            // never signalled here, so it returns promptly because SendFrame rechecks
            // _closing immediately after publishing the waiter under _rxLock. (The previous
            // design left one shared event signalled to achieve the same thing; per-attempt
            // waiters made that both impossible and unnecessary.)
            _closing = true;
            lock (_rxLock)
            {
                SignalWaiter(_currentWaiter);
            }

            // Wait for any in-flight SendFrame to finish before closing the port.
            lock (_txLock)
            {
                base.Close();
            }
        }
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        // Before any lock: a queued handler calling SendFrame() would need _txLock,
        // which this method is about to hold while base.Dispose() waits for the
        // executor to drain. Completing the channel first lets the pump finish its
        // backlog and exit instead of stalling until the drain timeout.
        CompleteCallbacks();

        lock (_lifecycleLock)
        {
            // Defensive: if Dispose() is called without a preceding Close(), still wake any
            // waiter, so a SendFrame parked on one is not left waiting out its full timeout
            // while teardown proceeds around it. (Nothing shared is disposed here — see the
            // note further down.)
            _closing = true;
            lock (_rxLock)
            {
                SignalWaiter(_currentWaiter);
            }

            lock (_txLock)
            {
                _port.BytesReceived -= OnBytesReceived;
                // No shared events left to dispose: each waiter is owned and
                // disposed by the attempt that created it.
                base.Dispose();
            }
        }
    }
}
