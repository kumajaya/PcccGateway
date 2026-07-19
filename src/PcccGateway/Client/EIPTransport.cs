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
using PcccGateway.Common;

namespace PcccGateway.Client;

/// <summary>
/// EtherNet/IP (EIP) transport for PcccGateway.
///
/// Connects to a remote EIP device (e.g., SLC 5/05, MicroLogix 1100/1400)
/// and exchanges PCCC messages using the CIP Execute PCCC service (0x4B)
/// encapsulated in a SendRRData (0x006F) Unconnected Data item.
///
/// Send/receive are decoupled: <see cref="SendFrame"/> fires and forgets the
/// EIP packet; the background receive loop picks up every inbound packet,
/// extracts the inner PCCC frame, and raises <see cref="FrameReceived"/>.
/// The application layer matches responses to outstanding requests by TNS
/// (transaction number).
///
/// Thread safety and the event model are provided by <see cref="TCPBaseTransport"/>.
/// </summary>
public class EIPTransport : TCPBaseTransport
{
    // ── EIP Encapsulation command codes (CIP Vol 2, Appendix A) ──────────────
    private const ushort EIP_REGISTER_SESSION   = 0x0065;
    private const ushort EIP_UNREGISTER_SESSION = 0x0066;
    private const ushort EIP_SEND_RR_DATA       = 0x006F;  // request and response

    private const uint   EIP_STATUS_OK         = 0x00000000;
    private const ushort EIP_TRANSPORT_VERSION = 1;

    // ── CIP service codes ─────────────────────────────────────────────────────
    private const byte CIP_SERVICE_EXECUTE_PCCC       = 0x4B;  // Execute PCCC request
    private const byte CIP_SERVICE_EXECUTE_PCCC_REPLY = 0xCB;  // response (0x4B | 0x80)

    // ── Common Packet Format (CPF) item type codes ────────────────────────────
    private const ushort CPF_ITEM_NULL_ADDRESS     = 0x0000;
    private const ushort CPF_ITEM_UNCONNECTED_DATA = 0x00B2;
    private const ushort CPF_EXPECTED_ITEM_COUNT   = 2;

    // ── CIP path to the PCCC Object (class 0x67, instance 1) ─────────────────
    // Logical segment format: 0x20 = 8-bit Class ID, 0x24 = 8-bit Instance ID.
    // Path size = 2 words (4 bytes).
    private static readonly byte[] CipPcccPath = { 0x20, 0x67, 0x24, 0x01 };
    private const byte CipPcccPathSizeWords = 2;

    // ── Request ID embedded in every Execute PCCC frame ──────────────────────
    // Format: size(1) + vendorID(2 LE) + serialNumber(4 LE) = 7 bytes total.
    // Values are arbitrary client identifiers; any non-zero combination works.
    private static readonly byte[] CipRequestId =
    {
        0x07,               // size = 7 bytes follow
        0x3D, 0xF3,         // vendor ID = 0xF33D (little-endian)
        0x45, 0x43, 0x50, 0x21  // serial = 0x21504345 (little-endian)
    };
    private const int RequestIdLen = 7;

    // ── Layout constants ─────────────────────────────────────────────────────
    // Offsets from the start of the raw TCP packet:
    //   EIP encapsulation header            24 bytes → offset  0
    //   CPF prefix (iface 4 + timeout 2 + item count 2) → offset 24
    //   Null Address item (type 2 + len 2)   → offset 32
    //   Unconnected Data item header         → offset 36
    //   CIP payload                          → offset 40
    private const int EipHeaderLen     = 24;
    private const int CpfPrefixLen     = 8;
    private const int NullAddrItemLen  = 4;
    private const int UcdItemHeaderLen = 4;
    private const int CipPayloadOffset = EipHeaderLen + CpfPrefixLen + NullAddrItemLen + UcdItemHeaderLen; // 40

    /// <summary>Encapsulation options field: reserved, must be zero.</summary>
    private const int EipOptionsOffset = 20;

    // The same offsets expressed relative to the payload buffer the receive loop
    // hands us (i.e. packet offset minus EipHeaderLen). Parsing in payload
    // coordinates avoids rebuilding the whole packet on every inbound frame.
    private const int ItemCountOffset = CpfPrefixLen - 2;                    //  6
    private const int NullItemOffset  = CpfPrefixLen;                        //  8
    private const int UcdItemOffset   = CpfPrefixLen + NullAddrItemLen;      // 12
    private const int CipOffset       = CipPayloadOffset - EipHeaderLen;     // 16

    // ── Execute PCCC request CIP header (relative to the CIP payload start) ──
    // service(1) + path_size_words(1) + path(4) + request_id(7) = 13 bytes
    private const int CipReqHeaderLen = 1 + 1 + 4 + RequestIdLen; // 13

    // ── Execute PCCC response CIP header ─────────────────────────────────────
    // reply_service(1) + reserved(1) + general_status(1) + add_sts_size_words(1)
    // followed by (add_sts_size_words * 2) status bytes, then request_id(7)
    private const int CipRespFixedHeaderLen = 4;

    /// <summary>Minimum PCCC content: CMD, STS and the two TNS bytes.</summary>
    private const int MinPcccLen = 4;

    public const int DefaultPort = 44818;

    /// <summary>
    /// Initialises a new EIP transport.
    /// </summary>
    /// <param name="host">IP address or hostname of the target device.</param>
    /// <param name="port">EIP TCP port (default 44818).</param>
    /// <param name="connectTimeoutMs">Connection timeout (default 5000ms).</param>
    public EIPTransport(string host, int port = DefaultPort, int connectTimeoutMs = 5000)
        : base(host, port, connectTimeoutMs)
    {
    }

    protected override int HeaderSize => EipHeaderLen;

    /// <summary>
    /// The 16-bit encapsulation length covers CPF(8) + null item(4) + UCD
    /// header(4) + CIP header(13) + (inner - 2), i.e. 27 + inner, so an inner
    /// frame above 65508 would truncate that field.
    /// </summary>
    protected override int MaxPayloadLength => 65508;

    // ─── Session management ──────────────────────────────────────────────────

    /// <summary>
    /// Performs a synchronous EIP RegisterSession handshake.
    ///
    /// Reads and writes the stream directly because it must complete before the
    /// background receive loop starts. Per CIP Vol 2 §2-4.2 the session handle
    /// is in bytes 4–7 of the response header, not in the payload.
    /// </summary>
    protected override (uint sessionId, bool requiresUnregister) RegisterSession(NetworkStream stream)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        // RegisterSession request: header(24) + version(2) + options(2) = 28 bytes.
        w.Write(EIP_REGISTER_SESSION);   // command
        w.Write((ushort)4);              // length = 4 (version + options)
        w.Write((uint)0);                // session handle = 0 (not yet assigned)
        w.Write(EIP_STATUS_OK);          // status = 0
        w.Write((ulong)0);               // sender context = 0
        w.Write((uint)0);                // options = 0
        w.Write(EIP_TRANSPORT_VERSION);  // payload: protocol version = 1
        w.Write((ushort)0);              // payload: options flags = 0

        byte[] req = ms.ToArray();
        stream.Write(req, 0, req.Length);

        byte[] header = new byte[EipHeaderLen];
        ReadExactSync(stream, header);

        ushort responseCmd = BitConverter.ToUInt16(header, 0);
        if (responseCmd != EIP_REGISTER_SESSION)
            throw new InvalidDataException(
                $"RegisterSession: unexpected response command 0x{responseCmd:X4}.");

        uint responseStatus = BitConverter.ToUInt32(header, 8);
        if (responseStatus != EIP_STATUS_OK)
            throw new InvalidDataException(
                $"RegisterSession: non-zero status 0x{responseStatus:X8}.");

        // Encapsulation options (bytes 20-23) are reserved and must be zero; the
        // spec requires a receiver to discard a packet that sets them, because a
        // non-zero value asks for behaviour we do not implement.
        uint responseOptions = BitConverter.ToUInt32(header, EipOptionsOffset);
        if (responseOptions != 0)
            throw new InvalidDataException(
                $"RegisterSession: unsupported options 0x{responseOptions:X8}.");

        uint sessionHandle = BitConverter.ToUInt32(header, 4);

        // A real device never returns a zero handle. Accepting one would publish
        // the transport as open while every subsequent packet is silently
        // rejected by the peer, with nothing in the logs to explain it.
        if (sessionHandle == 0)
            throw new InvalidDataException("RegisterSession: server returned a zero session handle.");

        // Read and discard the payload (version + options, 4 bytes).
        ushort payloadLen = BitConverter.ToUInt16(header, 2);
        if (payloadLen > 0)
        {
            byte[] payload = new byte[payloadLen];
            ReadExactSync(stream, payload);
        }

        return (sessionHandle, true);
    }

    /// <summary>
    /// Sends an EIP UnregisterSession request (best-effort, no response expected).
    /// Called from the base class while holding _sendLock, and never when the
    /// connection is already known to be dead.
    /// </summary>
    protected override void UnregisterSession(NetworkStream stream, uint sessionId)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        w.Write(EIP_UNREGISTER_SESSION);
        w.Write((ushort)0);     // no payload
        w.Write(sessionId);
        w.Write(EIP_STATUS_OK);
        w.Write((ulong)0);
        w.Write((uint)0);

        byte[] req = ms.ToArray();
        try { stream.Write(req, 0, req.Length); }
        catch { /* ignore – connection may already be closed */ }
    }

    // ─── Packet builder ──────────────────────────────────────────────────────

    /// <summary>
    /// Builds a complete EIP SendRRData packet carrying one Execute PCCC
    /// request. The inner frame's DST and SRC bytes are stripped because the
    /// Execute PCCC service carries only CMD onward.
    /// </summary>
    protected override byte[] BuildRequestPacket(byte[] innerFrame, uint sessionId)
    {
        const int pcccDataOffset = 2;
        int pcccDataLen = innerFrame.Length - pcccDataOffset;

        // CIP payload: service(1) + pathSizeWds(1) + path(4) + requestId(7) + pccc
        int cipPayloadLen = CipReqHeaderLen + pcccDataLen;

        // Bytes after the 24-byte EIP header.
        int encapsulationLen = CpfPrefixLen + NullAddrItemLen + UcdItemHeaderLen + cipPayloadLen;
        int totalLen = EipHeaderLen + encapsulationLen;

        byte[] pkt = new byte[totalLen];   // zero-initialised by the runtime

        // ── EIP Encapsulation Header ─────────────────────────────────────────
        pkt[0] = (byte)(EIP_SEND_RR_DATA & 0xFF);
        pkt[1] = (byte)(EIP_SEND_RR_DATA >> 8);
        pkt[2] = (byte)(encapsulationLen & 0xFF);
        pkt[3] = (byte)(encapsulationLen >> 8);
        BitConverter.GetBytes(sessionId).CopyTo(pkt, 4);
        // status, sender context, options remain zero.

        // ── CPF prefix ───────────────────────────────────────────────────────
        // Interface handle and timeout remain zero; item count = 2.
        int itemCountPos = EipHeaderLen + ItemCountOffset;          // 30
        pkt[itemCountPos] = (byte)(CPF_EXPECTED_ITEM_COUNT & 0xFF);
        pkt[itemCountPos + 1] = (byte)(CPF_EXPECTED_ITEM_COUNT >> 8);

        // ── Null Address item ────────────────────────────────────────────────
        // type = 0x0000, length = 0 — both already zero.

        // ── Unconnected Data item header ─────────────────────────────────────
        int ucdPos = EipHeaderLen + UcdItemOffset;                  // 36
        pkt[ucdPos] = (byte)(CPF_ITEM_UNCONNECTED_DATA & 0xFF);     // 0xB2
        pkt[ucdPos + 1] = (byte)(CPF_ITEM_UNCONNECTED_DATA >> 8);   // 0x00
        pkt[ucdPos + 2] = (byte)(cipPayloadLen & 0xFF);
        pkt[ucdPos + 3] = (byte)(cipPayloadLen >> 8);

        // ── CIP Execute PCCC request ─────────────────────────────────────────
        int pos = CipPayloadOffset;                                 // 40
        pkt[pos++] = CIP_SERVICE_EXECUTE_PCCC;                      // 0x4B
        pkt[pos++] = CipPcccPathSizeWords;                          // 2 words
        Array.Copy(CipPcccPath, 0, pkt, pos, CipPcccPath.Length);
        pos += CipPcccPath.Length;                                  // 46
        Array.Copy(CipRequestId, 0, pkt, pos, CipRequestId.Length);
        pos += CipRequestId.Length;                                 // 53

        // ── PCCC payload (CMD, STS, TNS, FNC?, DATA…) ────────────────────────
        Array.Copy(innerFrame, pcccDataOffset, pkt, pos, pcccDataLen);

        return pkt;
    }

    // ─── Inner frame extractor ───────────────────────────────────────────────

    /// <summary>
    /// Extracts the inner PCCC frame from a received EIP SendRRData packet.
    ///
    /// For a response (service 0xCB) the CIP header is:
    /// <code>
    ///   reply_service   1   = 0xCB
    ///   reserved        1   = 0x00
    ///   general_status  1   = 0x00 (non-zero means error)
    ///   add_sts_words   1   = N (additional status WORDs that follow)
    ///   extended_status N*2
    ///   request_id      7
    ///   pccc_data       ...
    /// </code>
    ///
    /// For an unsolicited request (service 0x4B):
    /// <code>
    ///   service         1   = 0x4B
    ///   path_size_wds   1   = 2
    ///   path            4   = PCCC Object (0x20 0x67 0x24 0x01)
    ///   request_id      7
    ///   pccc_data       ...
    /// </code>
    ///
    /// The PCCC boundary is taken from the Unconnected Data item's declared
    /// length, not from the end of the encapsulation: any trailing CPF data or
    /// padding would otherwise be appended to the frame and silently corrupt it.
    ///
    /// The returned frame is prefixed with a synthetic DST (0x01) and SRC (0x00)
    /// so it matches the inner-frame format expected by the application layer.
    /// </summary>
    protected override byte[]? ExtractInnerFrame(byte[] header, byte[] payload, ushort dataLen)
    {
        // Need at least the CPF prefix, both item headers, and one CIP byte.
        if (dataLen <= CipOffset) return null;

        // ── Validate the CPF structure ───────────────────────────────────────
        ushort itemCount = ReadUInt16LE(payload, ItemCountOffset);
        if (itemCount != CPF_EXPECTED_ITEM_COUNT) return null;

        ushort nullItemType = ReadUInt16LE(payload, NullItemOffset);
        ushort nullItemLen  = ReadUInt16LE(payload, NullItemOffset + 2);
        if (nullItemType != CPF_ITEM_NULL_ADDRESS || nullItemLen != 0) return null;

        ushort ucdItemType = ReadUInt16LE(payload, UcdItemOffset);
        ushort ucdItemLen  = ReadUInt16LE(payload, UcdItemOffset + 2);
        if (ucdItemType != CPF_ITEM_UNCONNECTED_DATA) return null;

        // The CIP payload ends where the UCD item says it does.
        int cipEnd = CipOffset + ucdItemLen;
        if (ucdItemLen == 0 || cipEnd > dataLen) return null;

        // ── Dispatch on the CIP service code ─────────────────────────────────
        byte cipService = payload[CipOffset];
        bool isResponse = cipService == CIP_SERVICE_EXECUTE_PCCC_REPLY;
        bool isRequest  = cipService == CIP_SERVICE_EXECUTE_PCCC;
        if (!isResponse && !isRequest) return null;

        // The requester ID is length-prefixed: its first byte is the total size
        // including itself. Ours is the 7-byte minimum (size + vendor 2 +
        // serial 4), and a device echoes back exactly what we sent — but an
        // unsolicited request may carry a longer ID. Skipping a fixed 7 bytes
        // would then slice the frame mid-identifier and corrupt CMD/STS/TNS.
        int requesterIdStart;

        if (isResponse)
        {
            if (CipOffset + CipRespFixedHeaderLen >= cipEnd)
                return null;

            byte generalStatus = payload[CipOffset + 2];
            if (generalStatus != 0x00)
            {
                Logger.Warn(this, $"EIP: CIP Execute PCCC error, general status 0x{generalStatus:X2}");
                return null;
            }

            int addStsBytes = payload[CipOffset + 3] * 2;
            requesterIdStart = CipOffset + CipRespFixedHeaderLen + addStsBytes;
        }
        else
        {
            // An unsolicited request must actually target the PCCC Object;
            // without this check any packet whose byte at the CIP offset happens
            // to be 0x4B would be parsed as PCCC and injected into the app layer.
            if (CipOffset + 2 + CipPcccPath.Length >= cipEnd)
                return null;

            if (payload[CipOffset + 1] != CipPcccPathSizeWords)
                return null;
            for (int i = 0; i < CipPcccPath.Length; i++)
            {
                if (payload[CipOffset + 2 + i] != CipPcccPath[i])
                    return null;
            }

            requesterIdStart = CipOffset + 2 + CipPcccPath.Length;
        }

        if (requesterIdStart >= cipEnd)
            return null;

        int requesterIdLen = payload[requesterIdStart];
        if (requesterIdLen < RequestIdLen || requesterIdStart + requesterIdLen > cipEnd)
            return null;

        int pcccStart = requesterIdStart + requesterIdLen;

        if (pcccStart + MinPcccLen > cipEnd)
            return null; // not enough bytes for CMD, STS and TNS

        int pcccLen = cipEnd - pcccStart;

        byte[] innerFrame = new byte[2 + pcccLen];
        innerFrame[0] = 0x01;  // DST – not meaningful over EIP; set to 1
        innerFrame[1] = 0x00;  // SRC – not meaningful over EIP; set to 0
        Array.Copy(payload, pcccStart, innerFrame, 2, pcccLen);

        return innerFrame;
    }

    // ─── Header field extraction ─────────────────────────────────────────────

    protected override bool IsRelevantPacket(byte[] header) =>
        BitConverter.ToUInt16(header, 0) == EIP_SEND_RR_DATA &&
        BitConverter.ToUInt32(header, EipOptionsOffset) == 0;

    protected override uint GetSessionIdFromHeader(byte[] header) =>
        BitConverter.ToUInt32(header, 4);

    protected override uint GetStatusFromHeader(byte[] header) =>
        BitConverter.ToUInt32(header, 8);

    protected override ushort GetDataLengthFromHeader(byte[] header) =>
        BitConverter.ToUInt16(header, 2);
}
