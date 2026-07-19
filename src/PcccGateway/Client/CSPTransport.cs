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
/// <b>Status: IMPLEMENTED</b> — CSPv4 (Client Server Protocol) transport for PcccGateway.
///
/// Connects to a remote CSPv4 device (PLC-5E, SLC 5/05, SoftLogix 5, or a
/// gateway such as the 1761-NET-ENI) on TCP port 2222 — Allen-Bradley's
/// legacy "AB/Ethernet" PCCC transport, as opposed to CIP-encapsulated PCCC
/// on TCP/44818 which <see cref="EIPTransport"/> handles.
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
/// Send/receive are decoupled: <see cref="SendFrame"/> fires and forgets; the
/// background receive loop raises <see cref="FrameReceived"/> for every inbound
/// PCCC frame. The application layer matches responses to outstanding requests
/// by TNS (transaction number).
///
/// Thread safety and the event model are provided by <see cref="TCPBaseTransport"/>.
/// </summary>
public class CSPTransport : TCPBaseTransport
{
    // ── CSPv4 header field values ────────────────────────────────────────────
    private const byte MODE_REQUEST  = 0x01;
    private const byte MODE_RESPONSE = 0x02;

    private const byte SUBMODE_CONNECTION = 0x01;
    private const byte SUBMODE_PCCC       = 0x07;

    private const uint CSP_STATUS_OK = 0x00000000;

    // ── Layout constants ──────────────────────────────────────────────────────
    private const int CSPHeaderLen = 28;
    private const int LsapLocalLen = 4;

    private const byte LSAP_FORM_LOCAL = 0x00;

    /// <summary>Minimum PCCC content: CMD, STS and the two TNS bytes.</summary>
    private const int MinPcccLen = 4;

    /// <summary>
    /// LSAP "control" byte sent on every request. VERIFY: meaning still
    /// unconfirmed (the source dissector just calls it "Control Byte"). A
    /// real RSLinx CSPv4 session against a PLC-5 (2026-06-21 capture) showed
    /// RSLinx itself sending 0x05 here — but that's RSLinx's own station
    /// configuration talking, not necessarily a fixed protocol constant, so
    /// the default here stays 0x00 rather than copying that value blindly.
    /// Change via the constructor if a specific target requires it.
    /// </summary>
    private readonly byte _lsapControlByte;

    public const int DefaultPort = 2222;

    // First 4 context bytes on the REGISTER frame (Connection submode).
    // This exact value is REQUIRED by real PLC-5/40E (1785-L40E) hardware:
    // a register with an all-zero context is silently ignored (no reply), and
    // other non-zero values are rejected as well — only 00 04 00 05 is accepted
    // (verified against live hardware 2026-07). RSLinx uses the same value and
    // the server echoes it back in the reply. The meaning of the individual
    // bytes is still unknown, but the value is not arbitrary — do not change it.
    private static readonly byte[] RegisterContextPrefix = { 0x00, 0x04, 0x00, 0x05 };

    // Ensures the routed-LSAP notice is logged once per transport rather than on
    // every frame: on a DH+ network every single reply would otherwise log.
    // Deliberately per-instance, not static — two transports on two DH+ segments
    // are two separate findings, and a static flag would also leak between unit
    // tests, which this suite already runs serially to avoid.
    private int _routedLsapWarned;

    /// <summary>
    /// Initialises a new CSPv4 transport.
    /// </summary>
    /// <param name="host">IP address or hostname of the target device.</param>
    /// <param name="port">CSPv4 TCP port (default 2222).</param>
    /// <param name="connectTimeoutMs">Connection timeout (default 5000ms).</param>
    /// <param name="lsapControlByte">LSAP control byte sent on every request (default 0x00 — see field remarks).</param>
    public CSPTransport(string host, int port = DefaultPort, int connectTimeoutMs = 5000, byte lsapControlByte = 0x00)
        : base(host, port, connectTimeoutMs)
    {
        _lsapControlByte = lsapControlByte;
    }

    protected override int HeaderSize => CSPHeaderLen;

    /// <summary>
    /// data_length is 16 bits and covers LSAP(4) + PCCC(inner - 2) = inner + 2,
    /// so an inner frame above 65533 would truncate that field.
    /// </summary>
    protected override int MaxPayloadLength => 65533;

    // ─── Session management ──────────────────────────────────────────────────

    /// <summary>
    /// Performs a synchronous CSPv4 connection-register handshake (submode 0x01).
    /// VERIFY: the payload shape for this submode isn't documented even in the
    /// source dissector — assumed to be a bare 28-byte header with no LSAP/PCCC
    /// body on either side.
    /// </summary>
    /// <returns>
    /// The connection ID assigned by the server. CSPv4 has no unregister
    /// request — the pre-refactor transport sent nothing on close — so the
    /// second element is false.
    /// </returns>
    protected override (uint sessionId, bool requiresUnregister) RegisterSession(NetworkStream stream)
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

        stream.Write(req, 0, req.Length);

        byte[] header = new byte[CSPHeaderLen];
        ReadExactSync(stream, header);

        byte mode = header[0];
        byte submode = header[1];
        ushort dataLen = ReadUInt16BE(header, 2);
        uint conn = ReadUInt32BE(header, 4);
        uint status = ReadUInt32BE(header, 8);

        if (mode != MODE_RESPONSE || submode != SUBMODE_CONNECTION)
            throw new InvalidDataException(
                $"RegisterSession: unexpected mode/submode 0x{mode:X2}/0x{submode:X2}.");
        if (status != CSP_STATUS_OK)
            throw new InvalidDataException($"RegisterSession: non-zero status 0x{status:X8}.");
        if (conn == 0)
            throw new InvalidDataException("RegisterSession: server returned a zero connection ID.");

        if (dataLen > 0)
        {
            byte[] discard = new byte[dataLen];
            ReadExactSync(stream, discard);
        }

        return (conn, false);
    }

    // ─── Packet builder ──────────────────────────────────────────────────────

    /// <summary>
    /// Builds a complete CSPv4 PCCC-submode request packet:
    /// header + local-form LSAP (carrying the inner frame's DST/SRC) + PCCC.
    /// </summary>
    protected override byte[] BuildRequestPacket(byte[] innerFrame, uint sessionId)
    {
        byte dst = innerFrame[0];
        byte src = innerFrame[1];

        int pcccLen = innerFrame.Length - 2;
        int totalAfterHeader = LsapLocalLen + pcccLen;
        int totalLen = CSPHeaderLen + totalAfterHeader;

        byte[] pkt = new byte[totalLen];   // zero-initialised by the runtime

        // ── CSPv4 header ─────────────────────────────────────────────────────
        pkt[0] = MODE_REQUEST;
        pkt[1] = SUBMODE_PCCC;
        WriteUInt16BE(pkt, 2, (ushort)totalAfterHeader);
        WriteUInt32BE(pkt, 4, sessionId);
        // status (8-11) and context (12-27) remain zero.

        // ── LSAP, local form ─────────────────────────────────────────────────
        int lsapOffset = CSPHeaderLen;
        pkt[lsapOffset + 0] = dst;
        pkt[lsapOffset + 1] = _lsapControlByte;
        pkt[lsapOffset + 2] = src;
        pkt[lsapOffset + 3] = LSAP_FORM_LOCAL;

        // ── PCCC payload (CMD, STS, TNS, FNC?, DATA…) ────────────────────────
        Array.Copy(innerFrame, 2, pkt, lsapOffset + LsapLocalLen, pcccLen);

        return pkt;
    }

    // ─── Inner frame extractor ───────────────────────────────────────────────

    /// <summary>
    /// Extracts the inner PCCC frame from a received CSPv4 PCCC-submode
    /// packet's post-header payload (LSAP + PCCC bytes).
    /// </summary>
    protected override byte[]? ExtractInnerFrame(byte[] header, byte[] payload, ushort dataLen)
    {
        if (dataLen < LsapLocalLen + MinPcccLen)
            return null; // too short for LSAP plus a minimal PCCC header

        byte lsapFlag = payload[3];
        if (lsapFlag != LSAP_FORM_LOCAL)
        {
            // Routed form (DH+/DH-485) is not implemented. Without this notice
            // the symptom is an unexplained timeout, which is expensive to chase.
            if (Interlocked.Exchange(ref _routedLsapWarned, 1) == 0)
            {
                Logger.Warn(this,
                    $"CSP: routed-form LSAP (0x{lsapFlag:X2}) received and discarded — " +
                    "only the local form is implemented. Further occurrences are not logged.");
            }
            return null;
        }

        byte dst = payload[0];
        byte src = payload[2];

        int pcccLen = dataLen - LsapLocalLen;
        byte[] innerFrame = new byte[2 + pcccLen];
        innerFrame[0] = dst;
        innerFrame[1] = src;
        Array.Copy(payload, LsapLocalLen, innerFrame, 2, pcccLen);

        return innerFrame;
    }

    // ─── Header field extraction ─────────────────────────────────────────────

    protected override bool IsRelevantPacket(byte[] header) =>
        header[0] == MODE_RESPONSE && header[1] == SUBMODE_PCCC;

    protected override uint GetSessionIdFromHeader(byte[] header) =>
        ReadUInt32BE(header, 4);

    protected override uint GetStatusFromHeader(byte[] header) =>
        ReadUInt32BE(header, 8);

    protected override ushort GetDataLengthFromHeader(byte[] header) =>
        ReadUInt16BE(header, 2);
}
