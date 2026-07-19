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

using System.Net.Sockets;
using PcccGateway.Interface;
using PcccGateway.Common;

namespace PcccGateway.Client;

/// <summary>
/// Abstract base class for TCP-based transports (CSPv4 and EtherNet/IP).
/// Provides a unified lifecycle, send/receive loop, and diagnostic event
/// handling. Derived classes implement protocol-specific framing and parsing.
///
/// <para>
/// EVENT MODEL — deliberately synchronous, matching the pre-refactor
/// CSPTransport/EIPTransport behaviour:
/// <list type="bullet">
///   <item>
///     <c>RawFrameReceived</c> and <c>FrameReceived</c> are raised on the
///     receive-loop thread, raw strictly before decoded, for the same packet.
///     An earlier revision routed the raw events through a background channel
///     while leaving <c>FrameReceived</c> synchronous, which inverted that
///     order non-deterministically. There is no dispatcher task any more.
///   </item>
///   <item>
///     <c>RawFrameReceived</c> is raised for EVERY packet that passes the
///     session/status/relevance filters — including packets whose inner frame
///     cannot be extracted. Those are precisely the packets a diagnostic
///     subscriber needs to see.
///   </item>
///   <item>
///     <c>RawFrameSent</c> is raised after the bytes actually reach the wire,
///     outside <c>_sendLock</c>, so a subscriber may safely re-enter the
///     transport. It is never raised for a frame that failed to write.
///   </item>
///   <item>
///     Subscriber exceptions are isolated: a throwing handler can neither
///     change a transmission outcome nor tear down the receive loop.
///   </item>
/// </list>
/// </para>
///
/// <para>
/// NO CALLBACK EXECUTOR HERE — and that is deliberate, not an oversight.
/// <see cref="DF1BaseTransport"/> posts its receive-path events to a dedicated
/// serialized executor; this class raises them inline. The difference is in the
/// send path, not in care taken: a DF1 <c>SendFrame</c> blocks waiting for a
/// link-layer ACK that only the receive path can parse, so an inline handler
/// calling back in starved the very parsing it depended on and the send failed
/// every time. <c>SendFrame</c> here writes and returns — nothing waits on the
/// receive loop — so that cycle cannot form and an executor would buy only
/// indirection.
///
/// What does still apply: a handler runs ON the receive loop, so one that blocks
/// stops this transport reading, and the peer's data backs up in the TCP window.
/// Handlers must return promptly. Calling <c>Close()</c> or <c>Dispose()</c> from
/// a handler is safe — the thread marker below makes teardown skip waiting for
/// the loop it is standing on.
/// </para>
///
/// <para>
/// TEARDOWN — <c>Close()</c> cancels the receive loop, waits for it to exit
/// (skipped when called from the loop itself), then releases the socket. The
/// session generation guards against a stale loop closing a newer session.
/// </para>
///
/// <para>
/// OVERRIDABLE CONTRACT — every abstract/virtual member below is called either
/// under <c>_sendLock</c> or on the receive-loop thread. Implementations must be
/// pure: no I/O, no event raising, no locking, no blocking.
/// </para>
/// </summary>
public abstract class TCPBaseTransport : ITransport
{
    // ─── Lifecycle & synchronisation ─────────────────────────────────────────

    /// <summary>Serialises the whole Open()/Close()/Dispose() lifecycle.</summary>
    private readonly object _lifecycleLock = new object();

    /// <summary>Protects _isClosed, _sessionGeneration, _stream, _tcp, _sessionId, _isRegistered, _rxCts, _rxTask.</summary>
    private readonly object _closeLock = new object();

    /// <summary>Serialises all writes to the stream (registration and SendFrame).</summary>
    private readonly object _sendLock = new object();

    // Session generation: incremented on every successful Open().
    private uint _sessionGeneration;

    // Starts closed: a Close() before the first Open() is a no-op.
    private bool _isClosed = true;
    private volatile bool _disposed;

    // TCP resources (guarded by _closeLock).
    private TcpClient? _tcp;
    private NetworkStream? _stream;

    // Session identifier (connection ID for CSP, session handle for EIP).
    private uint _sessionId;
    private bool _requiresUnregister;

    // True on a thread currently executing a receive-loop callback. Lets
    // Close()/Dispose() detect that they were called from inside a
    // FrameReceived/RawFrameReceived handler — which runs synchronously ON the
    // receive loop — and skip waiting for that loop to finish.
    //
    // Per-thread rather than a single field: a handler that closes and reopens
    // the transport leaves the OLD receive loop still inside this callback while
    // the NEW loop starts raising its own. Two loops writing one shared field
    // would clobber each other's marker, and a callback-initiated Close() would
    // then wait on a receive task it is standing on until the drain timeout.
    //
    // Deliberately not disposed: a receive loop that outlived the drain timeout
    // may still read it, and ThreadLocal throws once disposed. The footprint is
    // one slot per transport instance, and transports are long-lived.
    private readonly ThreadLocal<bool> _inReceiveCallback = new();

    // Receive loop (guarded by _closeLock).
    private CancellationTokenSource? _rxCts;
    private Task? _rxTask;

    /// <summary>
    /// Signalled when teardown is complete. Reset when a teardown is claimed,
    /// Set when the socket and receive loop are fully released.
    /// </summary>
    private readonly ManualResetEventSlim _teardownComplete = new(true);

    /// <summary>How long Close() waits for the receive loop to exit.</summary>
    private const int ReceiveLoopDrainTimeoutMs = 1000;

    // ─── Events ──────────────────────────────────────────────────────────────

    /// <inheritdoc/>
    public event EventHandler<byte[]>? FrameReceived;

    /// <inheritdoc/>
    public event EventHandler<byte[]>? RawFrameSent;

    /// <inheritdoc/>
    public event EventHandler<byte[]>? RawFrameReceived;

    // ─── Properties ──────────────────────────────────────────────────────────

    /// <inheritdoc/>
    public bool IsOpen
    {
        get
        {
            lock (_closeLock)
                return !_disposed && !_isClosed && _tcp?.Connected == true;
        }
    }

    /// <summary>Protocol-specific header size in bytes (24 for EIP, 28 for CSP).</summary>
    protected abstract int HeaderSize { get; }

    /// <summary>
    /// Largest inner frame this transport's encapsulation can actually express,
    /// and nothing more. Derived classes MUST override with the value their own
    /// 16-bit length field permits, past which it would silently truncate and put
    /// a malformed packet on the wire.
    ///
    /// This is deliberately NOT a PCCC limit. AB publication 1770-6.5.16 caps a
    /// PCCC message at 244 bytes from FNC to Parameters inclusive, and an earlier
    /// revision enforced it here — but that is a statement about what a PLC will
    /// accept, not about what this transport can carry. Judging payloads is the
    /// PLC's job; a peer that dislikes a frame answers with a PCCC status code,
    /// which reaches the client and says far more than a gateway-side rejection
    /// that surfaces to it as an unexplained timeout. The gateway forwards PCCC
    /// without interpreting it, and a length ceiling is interpretation.
    /// </summary>
    protected abstract int MaxPayloadLength { get; }

    /// <summary>
    /// Smallest inner frame the packet builders can split without computing a
    /// negative length: DST and SRC, which both strip before framing the rest.
    ///
    /// Structural, like the maximum. A frame of 2..5 bytes carries no usable TNS
    /// and the peer will reject it, but that is the peer's verdict to give.
    /// </summary>
    protected virtual int MinInnerFrameLength => 2;

    /// <summary>Hostname or IP address of the remote device.</summary>
    protected string Host { get; }

    /// <summary>TCP port number.</summary>
    protected int Port { get; }

    /// <summary>Connection timeout in milliseconds.</summary>
    protected int ConnectTimeoutMs { get; }

    /// <summary>
    /// Deadline for each read once a message has started. The wait for the FIRST
    /// header byte is unbounded so idle connections stay connected; every read
    /// after that is bounded, dropping a peer that starts a message then stalls.
    /// </summary>
    protected virtual TimeSpan MessageReadTimeout => TimeSpan.FromSeconds(10);

    // ─── Construction ────────────────────────────────────────────────────────

    /// <summary>Initialises a new TCP transport.</summary>
    /// <param name="host">IP address or hostname of the target device.</param>
    /// <param name="port">TCP port number.</param>
    /// <param name="connectTimeoutMs">Connection timeout in milliseconds.</param>
    protected TCPBaseTransport(string host, int port, int connectTimeoutMs)
    {
        Host = host ?? throw new ArgumentNullException(nameof(host));
        Port = port;
        ConnectTimeoutMs = connectTimeoutMs;
    }

    // ─── ITransport.Open ─────────────────────────────────────────────────────

    /// <inheritdoc/>
    public void Open()
    {
        lock (_lifecycleLock)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
            if (IsOpen) return;

            // Clean up any previous session that wasn't fully torn down — and
            // refuse to continue if it is still running. Publishing a new
            // generation on top of a live socket would leave two sessions
            // overlapping, and the reusable _teardownComplete could then let the
            // older owner's Set() release a waiter belonging to the newer one.
            if (!CloseInternal(expectedGeneration: null, connectionLost: false))
                throw new InvalidOperationException(
                    "Cannot open: a previous teardown of this transport has not finished.");

            OpenLocked();
        }
    }

    /// <summary>
    /// Performs the actual connection and session registration.
    /// Must be called while holding _lifecycleLock.
    /// </summary>
    private void OpenLocked()
    {
        TcpClient? tcp = null;
        try
        {
            tcp = new TcpClient();
            tcp.NoDelay = true; // Disable Nagle algorithm

            // Enable TCP Keep-Alive for passive dead-connection detection
            // without sending application-level diagnostic frames.
            tcp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);

            var connectTask = tcp.ConnectAsync(Host, Port);
            try
            {
                if (!connectTask.Wait(ConnectTimeoutMs))
                    throw new TimeoutException($"Connection to {Host}:{Port} timed out after {ConnectTimeoutMs} ms.");
            }
            catch (AggregateException ae)
            {
                // Unwrap so the caller sees SocketException rather than
                // "One or more errors occurred".
                throw ae.InnerException ?? ae;
            }

            var stream = tcp.GetStream();

            // Bound synchronous stream I/O. This matters for two paths:
            //   - SendFrame's Write, and
            //   - the synchronous registration handshake below.
            // Without it, a half-open connection (peer crashed or unplugged
            // without RST/FIN — TCP alone cannot detect this) blocks forever,
            // long before any application-level response timeout applies.
            // NOTE: NetworkStream.ReadTimeout does NOT affect ReadAsync, so the
            // receive loop relies on MessageReadTimeout instead.
            stream.WriteTimeout = ConnectTimeoutMs;
            stream.ReadTimeout = ConnectTimeoutMs;

            // Register the session (protocol-specific). The handshake must
            // complete before the receive loop starts, otherwise both would
            // compete for the same incoming bytes.
            // RegisterSession signals failure by throwing; the flag it returns
            // says only whether teardown owes the peer an unregister request.
            uint sessionId;
            bool requiresUnregister;
            lock (_sendLock)
            {
                (sessionId, requiresUnregister) = RegisterSession(stream);
            }

            // Publish the new session under _closeLock.
            lock (_closeLock)
            {
                _isClosed = false;
                _tcp = tcp;
                _stream = stream;
                _sessionId = sessionId;
                _requiresUnregister = requiresUnregister;

                // Increment generation only after the session is fully
                // established, so a stale loop from a previous generation can
                // never observe — and therefore never close — the new one.
                _sessionGeneration++;

                _rxCts?.Dispose();
                _rxCts = new CancellationTokenSource();

                var token = _rxCts.Token;
                var gen = _sessionGeneration;

                // Assigned under _closeLock so CloseInternal always observes a
                // fully published task handle.
                _rxTask = Task.Run(() => ReceiveLoopAsync(token, gen));
            }
        }
        catch (Exception ex)
        {
            CloseInternal(expectedGeneration: null, connectionLost: true);
            try { tcp?.Dispose(); } catch { }
            throw new InvalidOperationException($"Failed to connect to {Host}:{Port} – {ex.Message}", ex);
        }
    }

    // ─── ITransport.Close / Dispose ──────────────────────────────────────────

    /// <inheritdoc/>
    public void Close()
    {
        lock (_lifecycleLock)
        {
            CloseInternal(expectedGeneration: null, connectionLost: false);
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        lock (_lifecycleLock)
        {
            if (_disposed) return;
            _disposed = true;
            CloseInternal(expectedGeneration: null, connectionLost: false);
        }

        // _teardownComplete is deliberately NOT disposed: a receive loop that
        // outlived the drain timeout still calls CloseInternal, which would then
        // throw ObjectDisposedException on a disposed event.
    }

    /// <summary>
    /// Atomically tears down the current session.
    /// </summary>
    /// <param name="expectedGeneration">
    /// When supplied, the teardown only proceeds if it matches the current
    /// generation, preventing a stale receive loop from killing a newer session.
    /// </param>
    /// <param name="connectionLost">
    /// True when the teardown is triggered by a dead connection. The unregister
    /// request is then skipped: writing to a half-open socket would block for
    /// the full WriteTimeout (ConnectTimeoutMs, 5 s by default) and cannot
    /// succeed anyway. This mirrors the pre-refactor CloseOnConnectionLost(),
    /// which cleared the registration flag before delegating to Close().
    /// </param>
    /// <param name="fromReceiveLoop">
    /// True when called by the receive loop on its way out, so the loop never
    /// waits for itself. An identity check (<c>Task.CurrentId != rxTask.Id</c>)
    /// is NOT reliable here: after the first await the continuation runs on a
    /// different task id than the one Task.Run handed back, so the guard would
    /// silently fail and every connection-loss teardown would burn the full
    /// drain timeout.
    /// </param>
    /// <returns>
    /// True when the session is fully torn down by the time this returns — either
    /// because this call did it, because there was nothing to do, or because the
    /// owning teardown finished while we waited. False when we gave up waiting and
    /// the previous session may still be live.
    /// </returns>
    private bool CloseInternal(uint? expectedGeneration, bool connectionLost, bool fromReceiveLoop = false)
    {
        NetworkStream? stream = null;
        TcpClient? tcp = null;
        CancellationTokenSource? rxCts = null;
        Task? rxTask = null;
        uint sessionId = 0;
        bool owesUnregister = false;
        bool claimed = false;

        // A handler invoked from ProcessReceivedPacket runs synchronously on the
        // receive loop. If it calls Close()/Dispose(), that call must not wait
        // for the loop it is standing on.
        if (_inReceiveCallback.Value)
            fromReceiveLoop = true;

        lock (_closeLock)
        {
            if (expectedGeneration.HasValue && expectedGeneration.Value != _sessionGeneration)
                return true; // stale loop – the session it refers to is already gone

            if (!_isClosed)
            {
                _isClosed = true;
                _teardownComplete.Reset();
                claimed = true;

                stream = _stream;
                tcp = _tcp;
                rxCts = _rxCts;
                rxTask = _rxTask;
                sessionId = _sessionId;              // snapshot before clearing
                owesUnregister = _requiresUnregister; // snapshot before clearing

                _stream = null;
                _tcp = null;
                _rxCts = null;
                _rxTask = null;
                _sessionId = 0;
                _requiresUnregister = false;
            }
        }

        if (!claimed)
        {
            // The receive loop must NEVER wait here. When Close() claims the
            // teardown it blocks on rxTask.Wait(); if the loop then blocked on
            // _teardownComplete — which only Close() sets — the two would wait
            // on each other until the drain timeout expired. The loop has
            // nothing left to do at this point, so it simply returns.
            if (fromReceiveLoop)
                return true;

            // Another caller owns the teardown; wait for it to finish. Report the
            // outcome rather than swallowing it: the owner can legitimately still
            // be inside UnregisterSession, which is bounded by WriteTimeout
            // (ConnectTimeoutMs, 5 s by default) and so can outlast this wait.
            if (_teardownComplete.Wait(ReceiveLoopDrainTimeoutMs * 4))
                return true;

            Logger.Warn(this, $"{GetType().Name}: timed out waiting for a concurrent teardown");
            return false;
        }

        try
        {
            // Signal the receive loop to stop before touching the stream.
            try { rxCts?.Cancel(); } catch { }

            // Close the socket while holding _sendLock, so an admitted SendFrame
            // cannot interpose a write after the close.
            lock (_sendLock)
            {
                if (owesUnregister && stream != null && !connectionLost)
                {
                    try { UnregisterSession(stream, sessionId); }
                    catch { /* best-effort */ }
                }
                try { stream?.Close(); } catch { }
            }

            try { tcp?.Close(); } catch { }

            // Wait for the receive loop to exit BEFORE disposing its token
            // source: the loop is very likely parked in ReadAsync with a
            // registration on that token. Skipped when we are the loop itself.
            if (rxTask != null && !rxTask.IsCompleted && !fromReceiveLoop)
            {
                try
                {
                    if (!rxTask.Wait(ReceiveLoopDrainTimeoutMs))
                        Logger.Warn(this, $"{GetType().Name}: receive loop did not exit within {ReceiveLoopDrainTimeoutMs} ms");
                }
                catch (AggregateException) { /* loop faulted; nothing to do */ }
            }

            try { rxCts?.Dispose(); } catch { }
        }
        finally
        {
            _teardownComplete.Set();
        }

        return true;
    }

    // ─── Diagnostic event isolation ──────────────────────────────────────────

    /// <summary>
    /// Invokes each subscriber of a data/diagnostic event independently,
    /// swallowing subscriber exceptions. A handler that throws must never change
    /// a transmission outcome (encouraging an unsafe retry) nor escape into the
    /// receive loop and tear the session down.
    /// </summary>
    /// <remarks>
    /// This isolation is stricter than the pre-refactor transports, where a
    /// throwing RawFrameReceived handler propagated into the loop's catch-all
    /// and silently killed the connection.
    /// </remarks>
    /// <param name="generation">
    /// When supplied, dispatch stops as soon as the session it names is no longer
    /// current. A subscriber may close — or close and reopen — the transport from
    /// inside its handler, and the subscribers after it must not then receive a
    /// frame belonging to a session that has already ended.
    ///
    /// This narrows the window rather than closing it: the check cannot be held
    /// across a callback without risking the deadlocks that a lease brings, so a
    /// frame can still slip through between the check and the invocation. See the
    /// note in ProcessReceivedPacket.
    /// </param>
    private void RaiseSafe(EventHandler<byte[]>? handler, byte[] data, uint? generation = null)
    {
        if (handler == null) return;
        var list = handler.GetInvocationList();

        for (int k = 0; k < list.Length; k++)
        {
            if (generation.HasValue)
            {
                lock (_closeLock)
                {
                    if (_isClosed || generation.Value != _sessionGeneration)
                        return;
                }
            }

            try { ((EventHandler<byte[]>)list[k]).Invoke(this, data); }
            catch { /* subscriber exception must not affect transport I/O */ }
        }
    }

    // ─── ITransport.SendFrame ────────────────────────────────────────────────

    /// <inheritdoc/>
    public void SendFrame(byte[] innerFrame)
    {
        if (innerFrame is null)
            throw new ArgumentNullException(nameof(innerFrame));

        if (innerFrame.Length < MinInnerFrameLength)
            throw new ArgumentException(
                $"Inner frame must be at least {MinInnerFrameLength} bytes (DST, SRC).",
                nameof(innerFrame));

        if (innerFrame.Length > MaxPayloadLength)
            throw new ArgumentOutOfRangeException(nameof(innerFrame),
                $"Inner frame of {innerFrame.Length} bytes exceeds what this encapsulation " +
                $"can express ({MaxPayloadLength} bytes); the length field would truncate.");

        byte[]? sentPacket = null;
        uint generation = 0;
        bool writeAttempted = false;

        try
        {
            // Hold _sendLock across both the session validation and the write so
            // a teardown cannot close the socket between them.
            lock (_sendLock)
            {
                NetworkStream stream;
                uint sessionId;
                lock (_closeLock)
                {
                    if (_isClosed || _disposed || _stream == null)
                        throw new InvalidOperationException("Transport is not open.");
                    stream = _stream;
                    sessionId = _sessionId;
                    generation = _sessionGeneration;
                }

                byte[] packet = BuildRequestPacket(innerFrame, sessionId);

                writeAttempted = true;
                stream.Write(packet, 0, packet.Length);

                // BuildRequestPacket returns a private array, so it can be
                // handed to subscribers without copying.
                if (RawFrameSent != null)
                    sentPacket = packet;
            }
        }
        catch when (writeAttempted)
        {
            // A failed or timed-out Write may have left a partial packet on the
            // wire. The peer's framing is then unrecoverable — every subsequent
            // packet would be parsed at the wrong offset — so the connection has
            // to be retired rather than reused. Done after _sendLock is released,
            // because CloseInternal takes it.
            CloseInternal(generation, connectionLost: true);
            throw;
        }

        // Raised outside _sendLock so a subscriber may re-enter the transport.
        if (sentPacket != null)
            RaiseSafe(RawFrameSent, sentPacket);
    }

    // ─── Receive loop ────────────────────────────────────────────────────────

    /// <summary>
    /// Reads one complete packet per iteration and dispatches it. Exits when the
    /// token is cancelled, when the peer closes the stream, or on any I/O error;
    /// <see cref="CloseInternal"/> is then called so resources are released even
    /// if the caller never called <see cref="Close"/>.
    /// </summary>
    private async Task ReceiveLoopAsync(CancellationToken ct, uint generation)
    {
        byte[] header = new byte[HeaderSize];
        byte[] payload = new byte[65536];
        bool connectionLost = true;

        while (!ct.IsCancellationRequested)
        {
            NetworkStream? stream;
            uint sessionId;
            lock (_closeLock)
            {
                if (generation != _sessionGeneration || _isClosed || _stream == null)
                {
                    connectionLost = false; // a teardown is already in progress
                    break;
                }
                stream = _stream;
                sessionId = _sessionId;
            }

            try
            {
                // Unbounded wait for the first byte of a new packet: an idle
                // connection must stay connected, interrupted only by shutdown.
                if (await ReadExactAsync(stream, header, 0, 1, ct).ConfigureAwait(false) < 1)
                    break; // connection closed gracefully

                // Each subsequent read gets its own fresh deadline, matching the
                // pre-refactor behaviour. A fresh source per read also avoids
                // reusing a timer that is already near — or past — its deadline.
                if (await ReadWithTimeoutAsync(stream, header, 1, HeaderSize - 1, ct).ConfigureAwait(false) < HeaderSize - 1)
                    break;

                uint packetSessionId = GetSessionIdFromHeader(header);
                uint status = GetStatusFromHeader(header);
                ushort dataLen = GetDataLengthFromHeader(header);

                if (dataLen > 0)
                {
                    if (dataLen > payload.Length)
                    {
                        // Oversized packet – drain and discard to stay in sync.
                        byte[] discard = new byte[dataLen];
                        if (await ReadWithTimeoutAsync(stream, discard, 0, dataLen, ct).ConfigureAwait(false) < dataLen)
                            break;
                        continue;
                    }

                    if (await ReadWithTimeoutAsync(stream, payload, 0, dataLen, ct).ConfigureAwait(false) < dataLen)
                        break;
                }

                if (packetSessionId != sessionId) continue;
                if (status != 0) continue;
                if (!IsRelevantPacket(header)) continue;

                // Re-check the generation: Close() could have completed and
                // Open() published a new session while we were blocked reading.
                lock (_closeLock)
                {
                    if (generation != _sessionGeneration || _isClosed)
                    {
                        connectionLost = false;
                        break;
                    }
                }

                ProcessReceivedPacket(header, payload, dataLen, generation);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                connectionLost = false; // Close() cancelled the token
                break;
            }
            catch (OperationCanceledException)
            {
                Logger.Warn(this, $"{GetType().Name} receive timed out while reading – closing connection");
                break;
            }
            catch (Exception ex)
            {
                // Closing the stream from Close() makes the pending read throw
                // ObjectDisposedException/IOException, which lands here even
                // though the shutdown is entirely normal. Only report a drop
                // that happens while the session is still supposed to be live —
                // an unexplained one is the hardest thing to diagnose in the
                // field, but logging every clean close would bury it.
                bool expected;
                lock (_closeLock)
                    expected = _isClosed || generation != _sessionGeneration;

                if (!expected)
                    Logger.Warn(this, $"{GetType().Name} receive loop exiting: {ex.GetType().Name}: {ex.Message}");
                break;
            }
        }

        // Clean up this generation. Intentionally does NOT take _lifecycleLock.
        CloseInternal(generation, connectionLost, fromReceiveLoop: true);
    }

    /// <summary>
    /// Handles a fully received and filtered packet: raises the raw diagnostic
    /// event, then extracts the inner frame and raises <see cref="FrameReceived"/>.
    /// </summary>
    /// <remarks>
    /// The raw event is raised BEFORE extraction and regardless of whether
    /// extraction succeeds, so a diagnostic subscriber still sees packets the
    /// parser rejects — exactly the ones worth looking at.
    /// </remarks>
    private void ProcessReceivedPacket(byte[] header, byte[] payload, ushort dataLen, uint generation)
    {
        // Mark the thread for the duration of the callbacks so a handler that
        // calls Close()/Dispose() is not made to wait for this very loop.
        bool previous = _inReceiveCallback.Value;
        _inReceiveCallback.Value = true;
        try
        {
            if (RawFrameReceived != null)
            {
                byte[] rawPacket = new byte[HeaderSize + dataLen];
                Array.Copy(header, 0, rawPacket, 0, HeaderSize);
                Array.Copy(payload, 0, rawPacket, HeaderSize, dataLen);
                RaiseSafe(RawFrameReceived, rawPacket, generation);
            }

            byte[]? inner = ExtractInnerFrame(header, payload, dataLen);
            if (inner == null) return;

            // No length judgement on the inbound path, deliberately. An earlier
            // revision discarded a reply outside the outbound size contract, which
            // meant a peer answering with slightly more than we expected had its
            // reply swallowed here and the client saw a request that never
            // completed. Whatever the peer sent is what the client asked for; the
            // extractor has already bounded every read against the declared
            // lengths, so passing it on cannot corrupt anything downstream.

            // A RawFrameReceived handler may have closed the transport, or
            // closed and reopened it. Delivering this packet now would hand a
            // response from the old session to subscribers of the new one,
            // where the application layer could match it to a recycled TNS.
            // Best-effort by construction: the check cannot be held across the
            // callback without risking deadlock, so it narrows the window
            // rather than closing it.
            lock (_closeLock)
            {
                if (_isClosed || generation != _sessionGeneration)
                    return;
            }

            RaiseSafe(FrameReceived, inner, generation);
        }
        finally
        {
            _inReceiveCallback.Value = previous;
        }
    }

    // ─── Abstract / virtual members ─────────────────────────────────────────
    // Contract: called under _sendLock or on the receive-loop thread. Must be
    // pure — no I/O, no events, no locking, no blocking.

    /// <summary>
    /// Performs the protocol-specific session registration handshake.
    /// Called while holding _sendLock, on the stream before it is published.
    /// </summary>
    /// <returns>
    /// The assigned session ID, and whether teardown owes the peer an
    /// <see cref="UnregisterSession"/> request. The flag is NOT a success
    /// indicator — a failed handshake must throw, so that Open() can never
    /// publish a session the peer has not accepted. CSP registers but has
    /// nothing to unregister, and so returns false.
    /// </returns>
    protected abstract (uint sessionId, bool requiresUnregister) RegisterSession(NetworkStream stream);

    /// <summary>
    /// Sends an optional unregister request. Default is a no-op.
    /// Called while holding _sendLock, and never when the connection is known
    /// to be dead.
    /// </summary>
    protected virtual void UnregisterSession(NetworkStream stream, uint sessionId) { }

    /// <summary>
    /// Builds the complete outbound packet from the inner PCCC frame. The
    /// returned array is written to the stream and then handed to
    /// <see cref="RawFrameSent"/> subscribers, so it must not be pooled or reused.
    /// </summary>
    /// <param name="innerFrame">[DST, SRC, CMD, STS, TNS_LO, TNS_HI, FNC?, DATA...]</param>
    /// <param name="sessionId">The current session ID (connection ID or handle).</param>
    protected abstract byte[] BuildRequestPacket(byte[] innerFrame, uint sessionId);

    /// <summary>
    /// Extracts the inner PCCC frame from a received packet, or returns null if
    /// the packet does not carry a valid PCCC frame.
    /// </summary>
    protected abstract byte[]? ExtractInnerFrame(byte[] header, byte[] payload, ushort dataLen);

    /// <summary>Returns true if the packet should be processed further.</summary>
    protected abstract bool IsRelevantPacket(byte[] header);

    /// <summary>Extracts the session ID from the packet header.</summary>
    protected abstract uint GetSessionIdFromHeader(byte[] header);

    /// <summary>Extracts the status code from the packet header.</summary>
    protected abstract uint GetStatusFromHeader(byte[] header);

    /// <summary>Extracts the data length (payload size) from the packet header.</summary>
    protected abstract ushort GetDataLengthFromHeader(byte[] header);

    // ─── I/O helpers ─────────────────────────────────────────────────────────

    /// <summary>
    /// Reads exactly <paramref name="count"/> bytes, bounded by
    /// <see cref="MessageReadTimeout"/>. Used for every read after the first
    /// header byte of a message.
    /// </summary>
    private async Task<int> ReadWithTimeoutAsync(NetworkStream stream, byte[] buffer,
                                                 int offset, int count, CancellationToken ct)
    {
        using var timeout = new CancellationTokenSource(MessageReadTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
        return await ReadExactAsync(stream, buffer, offset, count, linked.Token).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads exactly <paramref name="count"/> bytes. Returns fewer only when the
    /// stream is closed by the peer.
    /// </summary>
    private static async Task<int> ReadExactAsync(NetworkStream stream, byte[] buffer,
                                                  int offset, int count, CancellationToken token)
    {
        int total = 0;
        while (total < count)
        {
            int n = await stream.ReadAsync(buffer, offset + total, count - total, token).ConfigureAwait(false);
            if (n == 0) break;
            total += n;
        }
        return total;
    }

    /// <summary>
    /// Synchronous read used during the registration handshake, before the
    /// receive loop starts. Bounded by NetworkStream.ReadTimeout.
    /// </summary>
    protected static void ReadExactSync(NetworkStream stream, byte[] buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int n = stream.Read(buffer, total, buffer.Length - total);
            if (n == 0) throw new IOException("Connection closed during registration.");
            total += n;
        }
    }

    // ─── Big-endian helpers (CSP uses big-endian; EIP uses little-endian) ────

    /// <summary>Writes a 16-bit value in big-endian order.</summary>
    protected static void WriteUInt16BE(byte[] buf, int offset, ushort value)
    {
        buf[offset] = (byte)(value >> 8);
        buf[offset + 1] = (byte)(value & 0xFF);
    }

    /// <summary>Writes a 32-bit value in big-endian order.</summary>
    protected static void WriteUInt32BE(byte[] buf, int offset, uint value)
    {
        buf[offset] = (byte)(value >> 24);
        buf[offset + 1] = (byte)(value >> 16);
        buf[offset + 2] = (byte)(value >> 8);
        buf[offset + 3] = (byte)(value & 0xFF);
    }

    /// <summary>Reads a 16-bit value in big-endian order.</summary>
    protected static ushort ReadUInt16BE(byte[] buf, int offset) =>
        (ushort)((buf[offset] << 8) | buf[offset + 1]);

    /// <summary>Reads a 32-bit value in big-endian order.</summary>
    protected static uint ReadUInt32BE(byte[] buf, int offset) =>
        ((uint)buf[offset] << 24) | ((uint)buf[offset + 1] << 16) |
        ((uint)buf[offset + 2] << 8) | buf[offset + 3];

    /// <summary>Reads a 16-bit value in little-endian order.</summary>
    protected static ushort ReadUInt16LE(byte[] buf, int offset) =>
        (ushort)(buf[offset] | (buf[offset + 1] << 8));
}
