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
/// EtherNet/IP (EIP) transport for PCCCComm.
///
/// Connects to a remote EIP device (e.g., SLC 5/05, MicroLogix 1100/1400)
/// and exchanges PCCC messages using the CIP Execute PCCC service (0x4B)
/// encapsulated in a SendRRData (0x006F) Unconnected Data item.
///
/// Send/receive are decoupled: <see cref="SendFrame"/> fires and forgets the
/// EIP packet; the background receive loop picks up every inbound packet,
/// extracts the inner PCCC frame, and raises <see cref="FrameReceived"/>.
/// The <see cref="PCCCComm"/> application layer matches responses to
/// outstanding requests by TNS (transaction number).
///
/// Thread safety: concurrent calls to <see cref="SendFrame"/> are serialised
/// by <c>_sendLock</c>. The receive loop runs on a dedicated thread-pool
/// task and reads through a private buffer that is never shared with the
/// send path.
/// </summary>
public class EIPTransport : ITransport
{
    // ── EIP Encapsulation command codes (CIP Vol 2, Appendix A) ──────────────
    private const ushort EIP_REGISTER_SESSION   = 0x0065;
    private const ushort EIP_UNREGISTER_SESSION = 0x0066;
    private const ushort EIP_SEND_RR_DATA       = 0x006F;  // used for both request and response

    private const uint   EIP_STATUS_OK          = 0x00000000;
    private const ushort EIP_TRANSPORT_VERSION  = 1;

    // ── CIP service codes ─────────────────────────────────────────────────────
    private const byte CIP_SERVICE_EXECUTE_PCCC       = 0x4B;  // Execute PCCC request
    private const byte CIP_SERVICE_EXECUTE_PCCC_REPLY = 0xCB;  // Execute PCCC response (0x4B | 0x80)

    // ── Common Packet Format (CPF) item type codes ────────────────────────────
    private const ushort CPF_ITEM_UNCONNECTED_DATA = 0x00B2;

    // ── CIP path to the PCCC Object (class 0x67, instance 1) ─────────────────
    // Logical segment format: 0x20 = 8-bit Class ID, 0x24 = 8-bit Instance ID.
    // Path size = 2 words (4 bytes).
    private static readonly byte[] CipPcccPath = { 0x20, 0x67, 0x24, 0x01 };

    // ── Request ID embedded in every Execute PCCC frame ──────────────────────
    // Format: size(1) + vendorID(2 LE) + serialNumber(4 LE) = 7 bytes total.
    // Values are arbitrary client identifiers; any non-zero combination works.
    private static readonly byte[] CipRequestId =
    {
        0x07,               // size = 7 bytes follow
        0x3D, 0xF3,         // vendor ID = 0xF33D (little-endian)
        0x45, 0x43, 0x50, 0x21  // serial = 0x21504345 (little-endian)
    };

    // ── Layout constants (all offsets from the start of the raw TCP packet) ──
    // EIP encapsulation header is always 24 bytes.
    // CPF prefix (Interface Handle 4 + Timeout 2 + Item Count 2) = 8 bytes → offset 24.
    // Null Address item (type 2 + length 2) = 4 bytes → offset 32.
    // Unconnected Data item header (type 2 + length 2) = 4 bytes → offset 36.
    // CIP payload starts at offset 40.
    private const int EipHeaderLen     = 24;
    private const int CpfPrefixLen     = 8;   // Interface Handle + Timeout + Item Count
    private const int NullAddrItemLen  = 4;   // type + length (both zero)
    private const int UcdItemHeaderLen = 4;   // type + length fields of Unconnected Data item
    private const int CipPayloadOffset = EipHeaderLen + CpfPrefixLen + NullAddrItemLen + UcdItemHeaderLen; // 40

    // ── Execute PCCC request CIP header layout (relative to CipPayloadOffset) ─
    // service(1) + path_size_words(1) + path(4) + request_id(7) = 13 bytes
    private const int CipReqHeaderLen = 1 + 1 + 4 + 7; // 13

    // ── Execute PCCC response CIP header layout (relative to CipPayloadOffset) ─
    // reply_service(1) + reserved(1) + general_status(1) + add_sts_size_words(1) = 4 bytes
    // followed by (add_sts_size_words * 2) extended status bytes, then request_id(7)
    private const int CipRespFixedHeaderLen = 4; // before extended status and request ID

    public const int DefaultPort = 44818;

    private readonly string _host;
    private readonly int    _port;
    private readonly int    _connectTimeoutMs;

    private TcpClient?     _tcp;
    private NetworkStream? _stream;
    private uint           _sessionHandle;
    private bool           _isRegistered;
    private bool           _disposed;

    // Serialises all writes to the stream (both RegisterSession and SendFrame).
    private readonly object _sendLock = new object();

    private readonly object _closeLock = new object();
    private bool _isClosed = false;

    // CancellationTokenSource used to stop the receive loop gracefully on Close().
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

    /// <summary>
    /// Initialises a new EIP transport.
    /// </summary>
    /// <param name="host">IP address or hostname of the target device.</param>
    /// <param name="port">EIP TCP port (default 44818).</param>
    /// <param name="connectTimeoutMs">Connection timeout (default 5000ms).</param>
    public EIPTransport(string host, int port = DefaultPort, int connectTimeoutMs = 5000)
    {
        _host = host ?? throw new ArgumentNullException(nameof(host));
        _port = port;
        _connectTimeoutMs = connectTimeoutMs;
    }

    // ── ITransport.Open ───────────────────────────────────────────────────────

    /// <inheritdoc/>
    /// <remarks>
    /// Connects the TCP socket, performs a synchronous RegisterSession
    /// handshake, then starts the background receive loop.
    /// Throws <see cref="InvalidOperationException"/> if any step fails;
    /// resources are released automatically in that case.
    /// </remarks>
    public void Open()
    {
        if (IsOpen) return;

        lock (_closeLock)
        {
            _isClosed = false;   // ← reset before opening new connection
        }

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
            // Propagate any connection error (refused, unreachable, etc.)
            if (connectTask.IsFaulted)
                throw connectTask.Exception!.InnerException ?? connectTask.Exception;

            _stream = _tcp.GetStream();

            // Bound every subsequent stream read/write to _connectTimeoutMs.
            // Without this, NetworkStream defaults to Socket.SendTimeout/
            // ReceiveTimeout = 0 (infinite): if the connection goes half-open
            // (peer crashes or is unplugged without sending RST/FIN — TCP
            // alone cannot detect this), a Write() or Read() call can block
            // forever. This happens *before* ResponseTimeoutMs ever gets a
            // chance to matter, since that timeout only bounds the reply-wait
            // in PCCCProtocol.SendRequest, not the raw socket I/O underneath
            // it. Confirmed in production: without this, a request could
            // hang indefinitely on a silently-dead connection, so the caller
            // never got a false/exception back to trigger reconnect — the
            // affected tag's last-known value was never invalidated either.
            _stream.WriteTimeout = _connectTimeoutMs;
            _stream.ReadTimeout  = _connectTimeoutMs;

            // Create a fresh lifecycle token for this connection session.
            // This allows Clean shutdown of idle reads and proper reconnection
            // after Close() is called.
            _lifecycleCts?.Dispose();
            _lifecycleCts = new CancellationTokenSource();
            _lifecycleToken = _lifecycleCts.Token;

            // RegisterSession reads/writes the stream directly and synchronously.
            // It must complete before the async receive loop starts, otherwise
            // both would compete for the same incoming bytes.
            RegisterSession();

            // Start the background receive loop after the session is established.
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

        // Signal the receive loop to stop before touching the stream.
        _rxCts?.Cancel();

        // Send UnregisterSession if the session is still active.
        if (_isRegistered)
        {
            try { UnregisterSession(); }
            catch { /* ignore – best-effort */ }
        }

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
        _rxCts         = null;
        _stream        = null;
        _tcp           = null;
        _isRegistered  = false;
        _sessionHandle = 0;
    }

    // ── ITransport.SendFrame ──────────────────────────────────────────────────

    /// <inheritdoc/>
    /// <remarks>
    /// Wraps the inner PCCC frame in a CIP Execute PCCC request (service 0x4B)
    /// and sends it as a SendRRData (0x006F) EIP packet. This method returns
    /// as soon as the bytes are written to the network stream; it does not
    /// wait for a response. The receive loop delivers the matching reply via
    /// <see cref="FrameReceived"/>.
    /// </remarks>
    public void SendFrame(byte[] innerFrame)
    {
        if (!IsOpen)
            throw new InvalidOperationException("Transport is not open.");

        if (innerFrame == null || innerFrame.Length == 0)
            throw new ArgumentException("Inner frame cannot be null or empty.", nameof(innerFrame));

        // Build the packet into a pooled buffer and write directly to the
        // stream — no intermediate persistent array needed.
        BuildAndSendRRDataPacket(innerFrame);
    }

    // ── Packet builder ────────────────────────────────────────────────────────

    /// <summary>
    /// Builds a complete EIP SendRRData packet that carries one Execute PCCC
    /// request into a pooled buffer, fires <see cref="RawFrameSent"/>, then
    /// writes the bytes directly to the stream under <c>_sendLock</c>.
    /// The pooled buffer is returned before this method exits, so no
    /// persistent array is allocated for the outbound packet.
    ///
    /// Packet layout (all multi-byte fields are little-endian):
    /// <code>
    /// [EIP header 24 bytes]
    ///   command      2   = 0x006F (SendRRData)
    ///   length       2   = total bytes that follow this header
    ///   session      4   = registered session handle
    ///   status       4   = 0 (OK)
    ///   senderCtx    8   = 0 (unused)
    ///   options      4   = 0
    /// [CPF prefix 8 bytes]
    ///   ifaceHandle  4   = 0
    ///   timeout      2   = 0
    ///   itemCount    2   = 2
    /// [Null Address item 4 bytes]
    ///   type         2   = 0x0000
    ///   length       2   = 0
    /// [Unconnected Data item]
    ///   type         2   = 0x00B2
    ///   length       2   = cipPayloadLen
    /// [CIP Execute PCCC request]
    ///   service      1   = 0x4B
    ///   pathSizeWds  1   = 2  (path is 4 bytes = 2 words)
    ///   path         4   = 0x20 0x67 0x24 0x01 (PCCC Object, instance 1)
    ///   requestId    7   = size(1) + vendorID(2 LE) + serialNo(4 LE)
    ///   pcccData     N   = innerFrame[2..] (DST and SRC bytes stripped)
    /// </code>
    /// </summary>
    /// <param name="innerFrame">
    /// Inner PCCC frame produced by <see cref="PacketBuilder"/>, including the
    /// leading DST and SRC bytes. DST and SRC are stripped here because the
    /// Execute PCCC service carries only CMD onward.
    /// </param>
    private void BuildAndSendRRDataPacket(byte[] innerFrame)
    {
        // The inner frame from PCCCComm always starts with DST (1 byte) and
        // SRC (1 byte). The CIP Execute PCCC payload begins at CMD, so we
        // skip those two bytes.
        const int pcccDataOffset = 2;
        int pcccDataLen = innerFrame.Length - pcccDataOffset;

        // CIP payload: service(1) + pathSizeWds(1) + path(4) + requestId(7) + pcccData
        int cipPayloadLen = CipReqHeaderLen + pcccDataLen;

        // Total bytes after the EIP 24-byte header:
        //   CPF prefix(8) + Null Address item(4) + UCD item header(4) + cipPayloadLen
        int encapsulationLen = CpfPrefixLen + NullAddrItemLen + UcdItemHeaderLen + cipPayloadLen;

        int totalLen = EipHeaderLen + encapsulationLen;

        byte[] pkt = ArrayPool<byte>.Shared.Rent(totalLen);
        try
        {
            // Clear only the bytes we will actually use.
            Array.Clear(pkt, 0, totalLen);

            // ── EIP Encapsulation Header ──────────────────────────────────────────
            // Bytes 0-1: command
            pkt[0] = (byte)(EIP_SEND_RR_DATA & 0xFF);
            pkt[1] = (byte)(EIP_SEND_RR_DATA >> 8);
            // Bytes 2-3: length (bytes after the 24-byte header)
            pkt[2] = (byte)(encapsulationLen & 0xFF);
            pkt[3] = (byte)(encapsulationLen >> 8);
            // Bytes 4-7: session handle (little-endian)
            byte[] temp = BitConverter.GetBytes(_sessionHandle);
            Array.Copy(temp, 0, pkt, 4, 4);
            // Bytes 8-11: status = 0x00000000 (already zero due to Clear)
            // Bytes 12-19: sender context = 0 (already zero)
            // Bytes 20-23: options = 0 (already zero)

            // ── CPF Prefix (offset 24) ────────────────────────────────────────────
            // Interface Handle (4 bytes) = 0 (already zero)
            // Timeout (2 bytes) = 0 (already zero)
            // Item Count (2 bytes) = 2
            pkt[30] = 0x02;   // item count low byte
            pkt[31] = 0x00;   // item count high byte

            // ── Null Address Item (offset 32) ─────────────────────────────────────
            // type = 0x0000 (already zero), length = 0 (already zero)

            // ── Unconnected Data Item header (offset 36) ──────────────────────────
            pkt[36] = (byte)(CPF_ITEM_UNCONNECTED_DATA & 0xFF);  // 0xB2
            pkt[37] = (byte)(CPF_ITEM_UNCONNECTED_DATA >> 8);    // 0x00
            pkt[38] = (byte)(cipPayloadLen & 0xFF);
            pkt[39] = (byte)(cipPayloadLen >> 8);

            // ── CIP Execute PCCC Request (offset 40 = CipPayloadOffset) ──────────
            int pos = CipPayloadOffset;
            pkt[pos++] = CIP_SERVICE_EXECUTE_PCCC;   // 0x4B
            pkt[pos++] = 0x02;                        // path size = 2 words
            Array.Copy(CipPcccPath, 0, pkt, pos, CipPcccPath.Length);
            pos += CipPcccPath.Length;                // pos = 46
            Array.Copy(CipRequestId, 0, pkt, pos, CipRequestId.Length);
            pos += CipRequestId.Length;               // pos = 53

            // ── PCCC payload (CMD, STS, TNS, FUNC?, DATA…) ───────────────────────
            Array.Copy(innerFrame, pcccDataOffset, pkt, pos, pcccDataLen);

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
    /// Extracts the inner PCCC frame from a received EIP SendRRData packet.
    ///
    /// For a response (service 0xCB), the CIP header layout is:
    /// <code>
    ///   reply_service   1   = 0xCB
    ///   reserved        1   = 0x00
    ///   general_status  1   = 0x00 (non-zero means error)
    ///   add_sts_words   1   = N (number of additional status WORDs that follow)
    ///   extended_status N*2 (present only when add_sts_words > 0)
    ///   request_id      7
    ///   pccc_data       ...
    /// </code>
    ///
    /// For an unsolicited request (service 0x4B), the CIP header layout is:
    /// <code>
    ///   service         1   = 0x4B
    ///   path_size_wds   1   = 2
    ///   path            4
    ///   request_id      7
    ///   pccc_data       ...
    /// </code>
    ///
    /// The returned frame is prefixed with a synthetic DST (0x01) and SRC (0x00)
    /// so it matches the inner-frame format expected by <see cref="PCCCComm"/>.
    /// </summary>
    /// <param name="packet">Complete raw EIP packet (header + CPF + CIP data).</param>
    /// <param name="isResponse">
    /// <c>true</c> for a response (service 0xCB); <c>false</c> for a request (0x4B).
    /// </param>
    /// <exception cref="InvalidDataException">
    /// Thrown when the packet is too short or contains a non-zero CIP general status.
    /// </exception>
    private static byte[] ExtractInnerFrame(byte[] packet, bool isResponse)
    {
        // CIP payload always begins at offset 40 (see CipPayloadOffset).
        int pos = CipPayloadOffset;

        int pcccDataStart;
        if (isResponse)
        {
            // Validate minimum response length:
            //   CIP fixed header(4) + request_id(7) + at least CMD(1) = 12 bytes
            if (pos + CipRespFixedHeaderLen + 7 + 1 > packet.Length)
                throw new InvalidDataException("Execute PCCC response is too short.");

            // Byte [pos+2]: CIP general status. 0x00 = success.
            byte generalStatus = packet[pos + 2];
            if (generalStatus != 0x00)
                throw new InvalidDataException(
                    $"CIP Execute PCCC error: general status 0x{generalStatus:X2}.");

            // Byte [pos+3]: number of additional status WORDs (each WORD = 2 bytes).
            byte addStsWords = packet[pos + 3];
            int addStsBytes  = addStsWords * 2;

            // PCCC data begins after: fixed header(4) + extended status + request ID(7)
            pcccDataStart = pos + CipRespFixedHeaderLen + addStsBytes + 7;
        }
        else
        {
            // Unsolicited request layout:
            //   service(1) + path_size_wds(1) + path(4) + request_id(7) = 13 bytes
            if (pos + CipReqHeaderLen + 1 > packet.Length)
                throw new InvalidDataException("Execute PCCC request is too short.");

            pcccDataStart = pos + CipReqHeaderLen;
        }

        if (pcccDataStart + 4 > packet.Length)
            throw new InvalidDataException("Not enough bytes for a valid PCCC frame.");

        int pcccDataLen = packet.Length - pcccDataStart;

        // Reconstruct the inner frame with a synthetic DST/SRC header.
        // PCCCComm expects: DST(1) + SRC(1) + CMD(1) + STS(1) + TNS_LO(1) + TNS_HI(1) + ...
        byte[] innerFrame = new byte[2 + pcccDataLen];
        innerFrame[0] = 0x01;  // DST – not meaningful over EIP; set to 1 (target node)
        innerFrame[1] = 0x00;  // SRC – not meaningful over EIP; set to 0
        Array.Copy(packet, pcccDataStart, innerFrame, 2, pcccDataLen);

        return innerFrame;
    }

    // ── Session management ────────────────────────────────────────────────────

    /// <summary>
    /// Performs a synchronous EIP RegisterSession handshake.
    ///
    /// This method reads and writes the stream directly (no async, no receive
    /// loop) because it must complete before the background loop starts.
    /// The session handle returned by the device is stored in
    /// <see cref="_sessionHandle"/> and is required for all subsequent packets.
    ///
    /// Per CIP Vol 2 §2-4.2: the session handle is in bytes 4–7 of the
    /// response header, not in the payload.
    /// </summary>
    private void RegisterSession()
    {
        using var ms = new MemoryStream();
        using var w  = new BinaryWriter(ms);

        // EIP RegisterSession request: header(24) + version(2) + options(2) = 28 bytes total.
        w.Write(EIP_REGISTER_SESSION);   // command
        w.Write((ushort)4);              // length = 4 (version + options)
        w.Write((uint)0);                // session handle = 0 (not yet assigned)
        w.Write(EIP_STATUS_OK);          // status = 0
        w.Write((ulong)0);               // sender context = 0
        w.Write((uint)0);                // EIP header: options = 0
        w.Write(EIP_TRANSPORT_VERSION);  // payload: protocol version = 1
        w.Write((ushort)0);              // payload: options flags = 0

        byte[] req = ms.ToArray();

        lock (_sendLock)
        {
            _stream!.Write(req, 0, req.Length);

            // Read the 24-byte response header synchronously.
            byte[] header = new byte[EipHeaderLen];
            ReadExactSync(_stream, header);

            ushort responseCmd = (ushort)(header[0] | (header[1] << 8));
            if (responseCmd != EIP_REGISTER_SESSION)
                throw new InvalidDataException(
                    $"RegisterSession: unexpected response command 0x{responseCmd:X4}.");

            uint responseStatus = BitConverter.ToUInt32(header, 8);
            if (responseStatus != EIP_STATUS_OK)
                throw new InvalidDataException(
                    $"RegisterSession: non-zero status 0x{responseStatus:X8}.");

            // Session handle is in bytes 4–7 of the response header (CIP Vol 2 §2-4.2).
            _sessionHandle = BitConverter.ToUInt32(header, 4);

            // Read and discard the payload (version + options, 4 bytes).
            ushort payloadLen = (ushort)(header[2] | (header[3] << 8));
            if (payloadLen > 0)
            {
                byte[] payload = new byte[payloadLen];
                ReadExactSync(_stream, payload);
            }

            _isRegistered = true;
        }
    }

    /// <summary>
    /// Sends an EIP UnregisterSession request (best-effort, no response expected).
    /// </summary>
    private void UnregisterSession()
    {
        if (!_isRegistered) return;

        using var ms = new MemoryStream();
        using var w  = new BinaryWriter(ms);

        w.Write(EIP_UNREGISTER_SESSION);
        w.Write((ushort)0);     // no payload
        w.Write(_sessionHandle);
        w.Write(EIP_STATUS_OK);
        w.Write((ulong)0);
        w.Write((uint)0);

        byte[] req = ms.ToArray();

        lock (_sendLock)
        {
            try { _stream!.Write(req, 0, req.Length); }
            catch { /* ignore – connection may already be closed */ }
        }

        _isRegistered = false;
    }

    // ── Background receive loop ───────────────────────────────────────────────

    /// <summary>
    /// Runs on a thread-pool task started by <see cref="Open"/>.
    ///
    /// Each iteration reads one complete EIP packet (header + payload) and,
    /// for SendRRData packets carrying an Execute PCCC response or unsolicited
    /// request, extracts the inner PCCC frame and raises
    /// <see cref="FrameReceived"/>.
    ///
    /// The loop exits cleanly when the <paramref name="ct"/> is cancelled
    /// (via <see cref="Close"/>) or when the TCP stream is closed by the
    /// remote end.  <see cref="CloseOnConnectionLost"/> is called on exit so
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
        // Use a private buffer so reads never overlap with the send path.
        byte[] header  = new byte[EipHeaderLen];
        byte[] payload = new byte[65536];

        // Combined cancellation token for shutdown and per-read timeout.
        using var timeoutCts = new CancellationTokenSource();
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        while (!ct.IsCancellationRequested && IsOpen && _stream != null)
        {
            try
            {
                // ── Read the fixed 24-byte EIP header ────────────────────────
                // Allow indefinite wait for the first byte of a new packet.
                // An idle connection should stay connected indefinitely, but
                // must respect shutdown requests via _lifecycleToken.
                if (await ReadExactAsync(header, 0, 1, idleFirstByte: true, ct) < 1)
                    break;  // connection closed gracefully

                // Arm a partial-header timeout for the remaining bytes.
                timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));
                if (await ReadExactAsync(header, 1, EipHeaderLen - 1, idleFirstByte: false, linkedCts.Token) < EipHeaderLen - 1)
                    break;  // connection closed gracefully
                timeoutCts.CancelAfter(Timeout.Infinite);

                ushort cmd     = (ushort)(header[0] | (header[1] << 8));
                ushort length  = (ushort)(header[2] | (header[3] << 8));
                uint   session = BitConverter.ToUInt32(header, 4);
                uint   status  = BitConverter.ToUInt32(header, 8);

                // ── Always read the declared payload to keep stream in sync ──
                // Skipping a packet without consuming its bytes would misalign
                // every subsequent read.
                if (length > 0)
                {
                    if (length > payload.Length)
                    {
                        // Oversized packet – drain and discard to stay in sync.
                        byte[] discard = new byte[length];
                        // Since we are mid-message, apply a timeout to prevent hanging.
                        timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));
                        int drained = await ReadExactAsync(discard, 0, length, idleFirstByte: false, linkedCts.Token);
                        timeoutCts.CancelAfter(Timeout.Infinite);
                        if (drained < length) break;
                        continue;
                    }

                    // Apply timeout for the payload read because the header was already received.
                    timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));
                    int payloadGot = await ReadExactAsync(payload, 0, length, idleFirstByte: false, linkedCts.Token);
                    timeoutCts.CancelAfter(Timeout.Infinite);
                    if (payloadGot < length) break;
                }

                // ── Filter by session handle and status ───────────────────────
                if (session != _sessionHandle) continue;
                if (status  != EIP_STATUS_OK)  continue;

                // ── Dispatch by command ───────────────────────────────────────
                if (cmd == EIP_SEND_RR_DATA)
                {
                    int totalLen = EipHeaderLen + length;
                    if (totalLen <= CipPayloadOffset) continue;

                    // Peek the CIP service byte directly from the receive buffer
                    // (payload offset = CipPayloadOffset - EipHeaderLen = 16)
                    // before allocating the combined packet, so frames with an
                    // irrelevant service code are discarded with zero allocation
                    // when RawFrameReceived is not subscribed.
                    const int cipServiceOffsetInPayload = CipPayloadOffset - EipHeaderLen; // 16
                    if (length <= cipServiceOffsetInPayload) continue;

                    byte cipService = payload[cipServiceOffsetInPayload];

                    bool isRelevant = cipService == CIP_SERVICE_EXECUTE_PCCC_REPLY ||
                                      cipService == CIP_SERVICE_EXECUTE_PCCC;

                    // Allocate the combined packet only when it will actually be used.
                    if (!isRelevant && RawFrameReceived == null) continue;

                    byte[] packet = new byte[totalLen];
                    Array.Copy(header,  0, packet, 0,           EipHeaderLen);
                    Array.Copy(payload, 0, packet, EipHeaderLen, length);

                    // Fire diagnostic event only when subscribed.
                    RawFrameReceived?.Invoke(this, packet);

                    if (isRelevant)
                    {
                        // 0xCB = Execute PCCC response; 0x4B = unsolicited Execute PCCC request.
                        bool isResponse = cipService == CIP_SERVICE_EXECUTE_PCCC_REPLY;
                        try
                        {
                            byte[] inner = ExtractInnerFrame(packet, isResponse);
                            FrameReceived?.Invoke(this, inner);
                        }
                        catch
                        {
                            // Malformed or error-status packet; discard silently.
                            // PCCCComm will time out the pending TNS.
                        }
                    }
                }
                // EIP_REGISTER_SESSION responses after initial handshake are ignored.
                // All other command codes are silently discarded.
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
                Logger.Warn(this, "EIP receive timed out while reading message payload – closing connection");
                break;
            }
            catch
            {
                break;  // TCP error or stream closed; exit and clean up
            }
        }

        // Clean up without sending UnregisterSession: the connection is already
        // gone or Close() has already been called.
        CloseOnConnectionLost();
    }

    /// <summary>
    /// Called when the receive loop exits due to a lost connection.
    /// Skips <see cref="UnregisterSession"/> because the TCP stream is gone,
    /// then delegates to <see cref="Close"/> for the rest of the teardown.
    /// </summary>
    private void CloseOnConnectionLost()
    {
        _isRegistered = false;  // prevent UnregisterSession from trying to write
        Close();
    }

    // ── I/O helpers ───────────────────────────────────────────────────────────

    /// <summary>
    /// Reads exactly <paramref name="count"/> bytes into
    /// <paramref name="buffer"/> starting at <paramref name="offset"/>.
    /// Returns the number of bytes actually read; a value less than
    /// <paramref name="count"/> indicates the stream was closed.
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
                // Wait indefinitely for the first byte of a new frame.
                // This keeps idle connections alive without periodic disconnects,
                // but respects shutdown signals via the caller's cancellation token.
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

    /// <summary>
    /// Synchronous counterpart of <see cref="ReadExactAsync"/> used exclusively
    /// by <see cref="RegisterSession"/> before the async loop starts.
    /// Throws <see cref="IOException"/> if the connection closes before
    /// all bytes are read.
    /// </summary>
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
