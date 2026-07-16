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
using System.Buffers;
using PcccGateway.Interface;
using PcccGateway.Common;

namespace PcccGateway.Client;

/// <summary>
/// <b>Status: IMPLEMENTED</b> — CSPv4 (Client Server Protocol) transport for PcccGateway.
///
/// Connects to a remote CSPv4 device (PLC-5E, SLC 5/05, SoftLogix 5, or a
/// gateway such as the 1761-NET-ENI) on TCP port 2222 — Allen-Bradley's
/// legacy "AB/Ethernet" PCCC transport, as opposed to CIP-encapsulated PCCC
/// on TCP/44818 which <see cref="EIPServer"/> handles.
///
/// ============================================================================
/// FRAME FORMAT — confirmed against kevinherron/wireshark-cspv4-pccc
/// (cspv4.lua), a reverse-engineered Wireshark dissector citing the
/// Senthivel/Ahmed/Roussev DFRWS 2017 PCCC forensics paper, Lynn Linse's
/// iatips.com notes, Chipkin's CSP article, and cross-checks against
/// Wireshark's own packet-cip.c PCCC value_string tables. Rockwell never
/// published an official CSPv4 spec, so treat this as the best available
/// secondary source rather than a primary one.
///
/// <code>
/// [ CSPv4 header — 28 bytes ][ LSAP — 4B local / 15B routed ][ PCCC — variable ]
/// </code>
///
/// CSPv4 header (all multi-byte integer fields BIG-ENDIAN, unlike EIP):
/// <code>
///   mode        1B   0x01 = Request, 0x02 = Response
///   submode     1B   0x01 = Connection (session register), 0x07 = PCCC
///   data_length 2B   length of everything AFTER this header (LSAP + PCCC)
///   conn_id     4B   assigned by the server on RegisterSession's reply;
///                    echoed by the client on every subsequent frame
///   status      4B   0 = OK
///   context     16B  opaque, echoed back by the peer (not used for
///                    correlation here — PCCC's own TNS field handles that)
/// </code>
///
/// LSAP, local form (4 bytes — the only form this class implements):
/// <code>
///   dst         1B   destination station address
///   control     1B   (role unconfirmed by the source dissector; comment
///                     there just calls it "Control Byte")
///   src         1B   source station address
///   lsap        1B   0x00 = local form, 0x01 = routed form (DH+/DH-485;
///                    NOT implemented here — see VALIDATION STATUS below)
/// </code>
///
/// PCCC, directly after LSAP — byte-identical to DF1's PCCC vocabulary:
/// <code>
///   CMD         1B   reply sets bit 0x40 (e.g. 0x0F request -&gt; 0x4F reply)
///   STS         1B   0x00 = success; 0x0F = "extended status follows"
///   TNS         2B   transaction number, LITTLE-ENDIAN (DF1 convention,
///                    unlike the big-endian CSPv4 header fields above)
///   EXT_STS     1B   present only when STS == 0x0F
///   FNC         1B   present only when (CMD &amp; ~0x40) is 0x06, 0x07, or 0x0F
///   DATA        ...  rest of the frame
/// </code>
///
/// ============================================================================
/// VALIDATION STATUS — as of 2026-06-21, validated against PCCCEmulator and
/// RSLinx OPC Server (PLC-5/40E detection, RSWho browse, data consistency):
///
///   1. Connection-submode (register) handshake — confirmed (bare 28-byte
///      header, data_length=0 both ways). Successfully registers and exchanges
///      PCCC frames with RSLinx and PCCCEmulator.
///
///   2. LSAP control byte — confirmed (echo back what client sends;
///      RSLinx uses 0x05, PCCCEmulator uses 0x00). Echoing works correctly.
///
///   3. Routed LSAP form (DH+/DH-485, 15 bytes) — NOT IMPLEMENTED.
///      Out of scope for direct Ethernet to a single station.
///
/// All core PCCC operations have been verified: read/write (int, float, string,
/// bit), multi-element, mode switching, initialize memory, and RMW (FNC 0x26).
/// Self-test suite passes 49/54 tests; remaining failures are PLC-5 handler
/// limitations, not transport-related.
/// ============================================================================
///
/// Send/receive are decoupled, mirroring <see cref="EIPServer"/>:
/// <see cref="SendFrame"/> fires and forgets; the background receive loop
/// raises <see cref="FrameReceived"/> for every inbound PCCC frame. The
/// <see cref="PCCCComm"/> application layer matches responses to outstanding
/// requests by TNS (transaction number).
///
/// A read timeout is applied only after the header is fully received,
/// preventing idle connections from being disconnected every 10 seconds.
/// Waiting for the first byte of a new packet is done using the
/// lifecycle token, which is cancelled during shutdown to allow graceful
/// termination without hanging.
/// </summary>
public class CSPTransport : ITransport
{
    // ── CSPv4 header field values ────────────────────────────────────────────
    private const byte MODE_REQUEST  = 0x01;
    private const byte MODE_RESPONSE = 0x02;

    private const byte SUBMODE_CONNECTION = 0x01;
    private const byte SUBMODE_PCCC       = 0x07;

    private const uint CSP_STATUS_OK = 0x00000000;

    // ── Layout constants ──────────────────────────────────────────────────────
    private const int CSPHeaderLen   = 28;
    private const int LsapLocalLen   = 4;

    /// <summary>
    /// LSAP "control" byte sent on every request. VERIFY: meaning still
    /// unconfirmed (the source dissector just calls it "Control Byte"). A
    /// real RSLinx CSPv4 session against a PLC-5 (2026-06-21 capture) showed
    /// RSLinx itself sending 0x05 here — but that's RSLinx's own station
    /// configuration talking, not necessarily a fixed protocol constant, so
    /// the default here stays 0x00 rather than copying that value blindly.
    /// Change via the constructor if a specific target requires it.
    /// </summary>
    private readonly byte LsapControlByte;

    public const int DefaultPort = 2222;

    private readonly string _host;
    private readonly int    _port;
    private readonly int    _connectTimeoutMs;

    private TcpClient?     _tcp;
    private NetworkStream? _stream;
    private uint           _connId;
    private bool           _disposed;

    // Serialises all writes to the stream (both registration and SendFrame).
    private readonly object _sendLock = new object();

    private readonly object _closeLock = new object();
    private bool _isClosed = false;

    private CancellationTokenSource? _rxCts;
    private Task? _rxTask;

    // Lifecycle token for graceful shutdown - cancels idle reads waiting for first byte.
    // Recreated on each Open() so that reconnection works after Close().
    private CancellationTokenSource? _lifecycleCts;
    private CancellationToken _lifecycleToken;

    public event EventHandler<byte[]>? FrameReceived;
    public event EventHandler<byte[]>? RawFrameSent;
    public event EventHandler<byte[]>? RawFrameReceived;

    /// <summary>
    /// Returns true when the TCP connection is established and the transport
    /// has not been disposed.
    /// </summary>
    public bool IsOpen => _tcp?.Connected == true && !_disposed;

    // First 4 context bytes on the REGISTER frame (Connection submode).
    // This exact value is REQUIRED by real PLC-5/40E (1785-L40E) hardware:
    // a register with an all-zero context is silently ignored (no reply), and
    // other non-zero values are rejected as well — only 00 04 00 05 is accepted
    // (verified against live hardware 2026-07). RSLinx uses the same value and
    // the server echoes it back in the reply. The meaning of the individual
    // bytes is still unknown, but the value is not arbitrary — do not change it.
    private static readonly byte[] RegisterContextPrefix = { 0x00, 0x04, 0x00, 0x05 };

    /// <summary>
    /// Initialises a new CSPv4 transport.
    /// </summary>
    /// <param name="host">IP address or hostname of the target device.</param>
    /// <param name="port">CSPv4 TCP port (default 2222).</param>
    /// <param name="connectTimeoutMs">Connection timeout (default 5000ms).</param>
    /// <param name="lsapControlByte">LSAP control byte sent on every request (default 0x00 — see field remarks).</param>
    public CSPTransport(string host, int port = DefaultPort, int connectTimeoutMs = 5000, byte lsapControlByte = 0x00)
    {
        _host = host ?? throw new ArgumentNullException(nameof(host));
        _port = port;
        _connectTimeoutMs = connectTimeoutMs;
        LsapControlByte = lsapControlByte;
    }

    // ── ITransport.Open ───────────────────────────────────────────────────────

    /// <inheritdoc/>
    public void Open()
    {
        if (IsOpen) return;

        lock (_closeLock) { _isClosed = false; }

        try
        {
            _tcp = new TcpClient();
            _tcp.NoDelay = true;  // Disable Nagle algorithm

            // Enable TCP Keep-Alive for passive dead-connection detection
            // without sending application-level diagnostic frames.
            _tcp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);

            var connectTask = _tcp.ConnectAsync(_host, _port);
            if (!connectTask.Wait(_connectTimeoutMs))
            {
                _tcp.Dispose();
                _tcp = null;
                throw new TimeoutException($"Connection to {_host}:{_port} timed out after {_connectTimeoutMs} ms.");
            }
            if (connectTask.IsFaulted)
                throw connectTask.Exception!.InnerException ?? connectTask.Exception;

            _stream = _tcp.GetStream();

            // See EIPTransport for the rationale: without an explicit timeout,
            // a half-open connection can block Write()/Read() forever, bypassing
            // ResponseTimeoutMs entirely (that only bounds the reply-wait).
            _stream.WriteTimeout = _connectTimeoutMs;
            _stream.ReadTimeout  = _connectTimeoutMs;

            // Create a fresh lifecycle token for this connection session.
            // This allows Clean shutdown of idle reads and proper reconnection
            // after Close() is called.
            _lifecycleCts?.Dispose();
            _lifecycleCts = new CancellationTokenSource();
            _lifecycleToken = _lifecycleCts.Token;

            // Registration must complete before the async receive loop starts.
            RegisterSession();

            _rxCts = new CancellationTokenSource();
            _rxTask = Task.Run(() => ReceiveLoopAsync(_rxCts.Token));
        }
        catch (Exception ex)
        {
            Close();
            throw new InvalidOperationException(
                $"Failed to connect to {_host}:{_port} – {ex.Message}", ex);
        }
    }

    // ── ITransport.Close ──────────────────────────────────────────────────────

    /// <inheritdoc/>
    public void Close()
    {
        lock (_closeLock)
        {
            if (_isClosed) return;
            _isClosed = true;
        }

        // Cancel and dispose the lifecycle token to wake any idle reads.
        if (_lifecycleCts != null)
        {
            try { _lifecycleCts.Cancel(); } catch { }
            _lifecycleCts.Dispose();
            _lifecycleCts = null;
        }

        _rxCts?.Cancel();

        try
        {
            _stream?.Close();
            _tcp?.Close();
        }
        catch { }

        if (_rxTask != null && !_rxTask.IsCompleted && Task.CurrentId != _rxTask.Id)
        {
            _rxTask.Wait(1000);
        }

        _rxTask?.Dispose();
        _rxTask = null;
        _rxCts?.Dispose();
        _rxCts        = null;
        _stream       = null;
        _tcp          = null;
        _connId       = 0;
    }

    // ── ITransport.SendFrame ──────────────────────────────────────────────────

    /// <inheritdoc/>
    /// <remarks>
    /// Wraps the inner PCCC frame in a CSPv4 PCCC-submode request: header +
    /// local-form LSAP (carrying the inner frame's DST/SRC bytes) + the raw
    /// PCCC bytes. Returns as soon as the bytes are written; it does not wait
    /// for a response. The receive loop delivers the matching reply via
    /// <see cref="FrameReceived"/>.
    /// </remarks>
    public void SendFrame(byte[] innerFrame)
    {
        if (!IsOpen)
            throw new InvalidOperationException("Transport is not open.");

        if (innerFrame == null || innerFrame.Length < 2)
            throw new ArgumentException("Inner frame must include at least DST and SRC bytes.", nameof(innerFrame));

        // Build the packet into a pooled buffer and write directly to the
        // stream — no intermediate persistent array needed.
        BuildAndSendPcccRequestPacket(innerFrame);
    }

    // ── Packet builder ────────────────────────────────────────────────────────

    /// <summary>
    /// Builds a complete CSPv4 PCCC-submode request packet into a pooled
    /// buffer, fires <see cref="RawFrameSent"/>, then writes the bytes
    /// directly to the stream under <c>_sendLock</c>. The pooled buffer is
    /// returned before this method exits, so no persistent array is allocated.
    /// </summary>
    /// <param name="innerFrame">
    /// Inner PCCC frame produced by <see cref="PacketBuilder"/>:
    /// [DST, SRC, CMD, STS, TNS_LO, TNS_HI, FNC?, DATA...].
    /// </param>
    private void BuildAndSendPcccRequestPacket(byte[] innerFrame)
    {
        byte dst = innerFrame[0];
        byte src = innerFrame[1];

        int pcccLen = innerFrame.Length - 2;
        int totalAfterHeader = LsapLocalLen + pcccLen;
        int totalLen = CSPHeaderLen + totalAfterHeader;

        byte[] pkt = ArrayPool<byte>.Shared.Rent(totalLen);
        try
        {
            // Clear only the bytes we will actually use.
            Array.Clear(pkt, 0, totalLen);

            // ── CSPv4 header ───────────────────────────────────────────────────
            pkt[0] = MODE_REQUEST;
            pkt[1] = SUBMODE_PCCC;
            WriteUInt16BE(pkt, 2, (ushort)totalAfterHeader);
            WriteUInt32BE(pkt, 4, _connId);
            // status (8-11) = 0 (already zero)
            // context (12-27) = 0 (already zero)

            // ── LSAP, local form ───────────────────────────────────────────────
            int lsapOffset = CSPHeaderLen;
            pkt[lsapOffset + 0] = dst;
            pkt[lsapOffset + 1] = LsapControlByte;
            pkt[lsapOffset + 2] = src;
            pkt[lsapOffset + 3] = 0x00;

            // ── PCCC payload (CMD, STS, TNS, FNC?, DATA…) ─────────────────────
            Array.Copy(innerFrame, 2, pkt, lsapOffset + LsapLocalLen, pcccLen);

            // Fire diagnostic event only when subscribed — avoids allocating a
            // trimmed copy of the rented buffer when nobody is listening.
            if (RawFrameSent != null)
            {
                byte[] copy = new byte[totalLen];
                Array.Copy(pkt, 0, copy, 0, totalLen);
                RawFrameSent.Invoke(this, copy);
            }

            // Write directly into the stream while holding _sendLock.
            // The pooled buffer must not outlive this lock scope.
            lock (_sendLock)
            {
                _stream!.Write(pkt, 0, totalLen);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(pkt, clearArray: false);
        }
    }

    // ── Inner frame extractor ─────────────────────────────────────────────────

    /// <summary>
    /// Extracts the inner PCCC frame from a received CSPv4 PCCC-submode
    /// packet's post-header payload (LSAP + PCCC bytes).
    /// </summary>
    /// <param name="payload">Bytes after the 28-byte header (length = data_length).</param>
    private static byte[] ExtractInnerFrame(byte[] payload)
    {
        if (payload.Length < LsapLocalLen + 4)
            throw new InvalidDataException("Payload too short for LSAP + minimal PCCC header.");

        byte lsapFlag = payload[3];
        if (lsapFlag != 0x00)
            throw new InvalidDataException(
                "Routed-form LSAP (DH+/DH-485) is not implemented — only local form is supported.");

        byte dst = payload[0];
        byte src = payload[2];

        int pcccLen = payload.Length - LsapLocalLen;
        byte[] innerFrame = new byte[2 + pcccLen];
        innerFrame[0] = dst;
        innerFrame[1] = src;
        Array.Copy(payload, LsapLocalLen, innerFrame, 2, pcccLen);

        return innerFrame;
    }

    // ── Session management ────────────────────────────────────────────────────

    /// <summary>
    /// Performs a synchronous CSPv4 connection-register handshake (submode
    /// 0x01). VERIFY: payload shape for this submode isn't documented even
    /// in the source dissector — assumed to be a bare 28-byte header with no
    /// LSAP/PCCC body on either side.
    /// </summary>
    private void RegisterSession()
    {
        byte[] req = new byte[CSPHeaderLen];
        req[0] = MODE_REQUEST;
        req[1] = SUBMODE_CONNECTION;
        WriteUInt16BE(req, 2, 0);  // data_length = 0
        WriteUInt32BE(req, 4, 0);  // conn_id = 0 (not yet assigned)
        WriteUInt32BE(req, 8, 0);  // status = 0

        // Register context must be non-zero: this CSPv4 PLC/gateway does NOT
        // reply to a register with an all-zero context. RSLinx uses the value
        // below and the server echoes it back in the reply. Byte meaning is
        // unconfirmed (see RegisterContextPrefix) — do not treat as arbitrary.
        RegisterContextPrefix.CopyTo(req, 12);

        lock (_sendLock)
        {
            _stream!.Write(req, 0, req.Length);

            byte[] header = new byte[CSPHeaderLen];
            ReadExactSync(_stream, header);

            byte mode    = header[0];
            byte submode = header[1];
            ushort dataLen = ReadUInt16BE(header, 2);
            uint   conn    = ReadUInt32BE(header, 4);
            uint   status  = ReadUInt32BE(header, 8);

            if (mode != MODE_RESPONSE || submode != SUBMODE_CONNECTION)
                throw new InvalidDataException(
                    $"RegisterSession: unexpected mode/submode 0x{mode:X2}/0x{submode:X2}.");

            if (status != CSP_STATUS_OK)
                throw new InvalidDataException(
                    $"RegisterSession: non-zero status 0x{status:X8}.");

            if (dataLen > 0)
            {
                byte[] discard = new byte[dataLen];
                ReadExactSync(_stream, discard);
            }

            _connId = conn;
        }
    }

    // ── Background receive loop ───────────────────────────────────────────────

    /// <summary>
    /// Runs on a thread-pool task started by <see cref="Open"/>.
    ///
    /// Each iteration reads one complete CSP packet (header + payload) and,
    /// for PCCC-submode packets, extracts the inner PCCC frame and raises
    /// <see cref="FrameReceived"/>.
    ///
    /// The loop exits cleanly when the <paramref name="ct"/> is cancelled
    /// (via <see cref="Close"/>) or when the TCP stream is closed by the
    /// remote end. <see cref="CloseOnConnectionLost"/> is called on exit so
    /// that resources are released even if the caller did not call
    /// <see cref="Close"/> explicitly.
    ///
    /// A read timeout is applied only after the header is fully received,
    /// preventing idle connections from being disconnected every 10 seconds.
    /// Waiting for the first byte of a new packet is done using the
    /// <see cref="_lifecycleToken"/>, which is cancelled during shutdown
    /// to allow graceful termination without hanging.
    /// </summary>
    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        byte[] header  = new byte[CSPHeaderLen];
        byte[] payload = new byte[65536];

        // Combined cancellation token for shutdown and per-read timeout.
        using var timeoutCts = new CancellationTokenSource();
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        while (!ct.IsCancellationRequested && IsOpen && _stream != null)
        {
            try
            {
                // ── Read the fixed CSP header ──────────────────────────────────
                // Allow indefinite wait for the first byte of a new packet.
                // An idle connection should stay connected indefinitely, but
                // must respect shutdown requests via the caller token.
                if (await ReadExactAsync(header, 0, 1, idleFirstByte: true, ct) < 1)
                    break; // connection closed gracefully

                timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));
                if (await ReadExactAsync(header, 1, CSPHeaderLen - 1, idleFirstByte: false, linkedCts.Token) < CSPHeaderLen - 1)
                    break; // connection closed gracefully
                timeoutCts.CancelAfter(Timeout.Infinite);

                byte   mode    = header[0];
                byte   submode = header[1];
                ushort dataLen = ReadUInt16BE(header, 2);
                uint   conn    = ReadUInt32BE(header, 4);
                uint   status  = ReadUInt32BE(header, 8);

                // ── Read the payload (if any) with a timeout ──────────────────
                // Since the header was received, the rest of the message must
                // arrive within a reasonable time to prevent slow-loris attacks.
                if (dataLen > 0)
                {
                    if (dataLen > payload.Length)
                    {
                        // Oversized packet – drain and discard to stay in sync.
                        byte[] discard = new byte[dataLen];
                        timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));
                        int drained = await ReadExactAsync(discard, 0, dataLen, idleFirstByte: false, linkedCts.Token);
                        timeoutCts.CancelAfter(Timeout.Infinite);
                        if (drained < dataLen) break;
                        continue;
                    }

                    timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));
                    int payloadGot = await ReadExactAsync(payload, 0, dataLen, idleFirstByte: false, linkedCts.Token);
                    timeoutCts.CancelAfter(Timeout.Infinite);
                    if (payloadGot < dataLen) break;
                }

                // ── Filter by connection ID and status ────────────────────────
                if (conn != _connId) continue;
                if (status != CSP_STATUS_OK) continue;
                if (mode != MODE_RESPONSE) continue;

                if (submode == SUBMODE_PCCC && dataLen >= LsapLocalLen)
                {
                    // Copy LSAP+PCCC payload out of the shared receive buffer
                    // before any event is fired (events may run on other threads).
                    byte[] framePayload = new byte[dataLen];
                    Array.Copy(payload, 0, framePayload, 0, dataLen);

                    // Allocate the combined diagnostic packet only when someone
                    // is actually subscribed — avoids a CSPHeaderLen+dataLen
                    // allocation on every received frame in normal operation.
                    if (RawFrameReceived != null)
                    {
                        byte[] fullPacket = new byte[CSPHeaderLen + dataLen];
                        Array.Copy(header,       0, fullPacket, 0,            CSPHeaderLen);
                        Array.Copy(framePayload, 0, fullPacket, CSPHeaderLen, dataLen);
                        RawFrameReceived.Invoke(this, fullPacket);
                    }

                    try
                    {
                        byte[] inner = ExtractInnerFrame(framePayload);
                        FrameReceived?.Invoke(this, inner);
                    }
                    catch
                    {
                        // Malformed/unsupported (e.g. routed LSAP) frame;
                        // discard. PCCCComm will time out the pending TNS.
                    }
                }
                // Connection-submode frames after the initial handshake are
                // not expected; silently discarded if they arrive.
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;  // Close() cancelled the token
            }
            catch (OperationCanceledException) when (_lifecycleCts?.IsCancellationRequested == true)
            {
                // Shutdown requested while waiting for first byte.
                Logger.Info(this, "Shutdown signal received during idle read – closing connection");
                break;
            }
            catch (OperationCanceledException) // timeout during payload read
            {
                Logger.Warn(this, "CSP receive timed out while reading payload – closing connection");
                break;
            }
            catch
            {
                break;  // TCP error or stream closed; exit and clean up
            }
        }

        CloseOnConnectionLost();
    }

    /// <summary>
    /// Called when the receive loop exits due to a lost connection.
    /// </summary>
    private void CloseOnConnectionLost()
    {
        Close();
    }

    // ── Big-endian helpers (CSPv4 header fields are big-endian, unlike EIP) ──

    private static void WriteUInt16BE(byte[] buf, int offset, ushort value)
    {
        buf[offset]     = (byte)(value >> 8);
        buf[offset + 1] = (byte)(value & 0xFF);
    }

    private static void WriteUInt32BE(byte[] buf, int offset, uint value)
    {
        buf[offset]     = (byte)(value >> 24);
        buf[offset + 1] = (byte)(value >> 16);
        buf[offset + 2] = (byte)(value >> 8);
        buf[offset + 3] = (byte)(value & 0xFF);
    }

    private static ushort ReadUInt16BE(byte[] buf, int offset) =>
        (ushort)((buf[offset] << 8) | buf[offset + 1]);

    private static uint ReadUInt32BE(byte[] buf, int offset) =>
        ((uint)buf[offset] << 24) | ((uint)buf[offset + 1] << 16) |
        ((uint)buf[offset + 2] << 8) | buf[offset + 3];

    // ── I/O helpers ───────────────────────────────────────────────────────────

    /// <summary>
    /// Reads exactly <paramref name="count"/> bytes into <paramref name="buffer"/>
    /// starting at <paramref name="offset"/>.
    ///
    /// When <paramref name="idleFirstByte"/> is true, the first byte of the
    /// read waits indefinitely using <see cref="_lifecycleToken"/>, which
    /// is cancelled during shutdown to allow graceful termination. Once the
    /// first byte arrives, the read is subject to the provided
    /// <paramref name="transactionToken"/> timeout to prevent slow-loris attacks.
    /// </summary>
    private async Task<int> ReadExactAsync(byte[] buffer, int offset, int count,
                                           bool idleFirstByte, CancellationToken transactionToken)
    {
        int total = 0;
        while (total < count)
        {
            int n;
            if (total == 0 && idleFirstByte)
            {
                // Wait indefinitely for the first byte of a new packet.
                // This keeps idle connections alive without periodic disconnects,
                // but respects shutdown requests from the caller.
                n = await _stream!.ReadAsync(buffer, offset, 1, transactionToken)
                                  .ConfigureAwait(false);
            }
            else
            {
                // Mid-message: use the provided token (which includes the timeout).
                n = await _stream!.ReadAsync(buffer, offset + total, count - total, transactionToken)
                                  .ConfigureAwait(false);
            }
            if (n == 0) break;
            total += n;
        }
        return total;
    }

    private static void ReadExactSync(NetworkStream stream, byte[] buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int n = stream.Read(buffer, total, buffer.Length - total);
            if (n == 0) throw new IOException("Connection closed during RegisterSession.");
            total += n;
        }
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_lifecycleCts != null)
        {
            try { _lifecycleCts.Cancel(); } catch { }
            _lifecycleCts.Dispose();
            _lifecycleCts = null;
        }
        Close();
    }
}
