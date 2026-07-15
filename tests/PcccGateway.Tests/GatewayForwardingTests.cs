using System.Net;
using System.Net.Sockets;
using PcccGateway.Interface;
using Xunit;

namespace PcccGateway.Tests;

/// <summary>
/// Exercises <see cref="Gateway"/>'s core job — forwarding a PCCC request from an
/// EIP client through to the PLC-side <see cref="ITransport"/> and routing the
/// reply back to the correct client with its original TNS restored — as a real
/// end-to-end flow. A real EIP client talks over a real loopback TCP socket to
/// Gateway's own <c>EIPServerTransport</c>; only the PLC side is faked, via a
/// minimal <see cref="ITransport"/> double, since that's the boundary Gateway
/// doesn't own.
/// <para>
/// This does not exist to re-test EIP encapsulation parsing in isolation (that's
/// <c>EIPServerBoundaryTests</c>'s job) — it exists because nothing previously
/// verified that a request actually makes it all the way through
/// <c>OnEipPduReceived</c> → TNS rewrite → <c>ITransport.SendFrame</c> →
/// <c>ITransport.FrameReceived</c> → <c>OnPlcFrameReceived</c> → TNS restore →
/// back out over the wire to the client that sent it.
/// </para>
/// </summary>
public class GatewayForwardingTests
{
    // ── CIP Execute PCCC request layout (see EIPServerTransport.ExtractAndDispatchPCCC) ──
    // service(1) + pathSize(1) + path(4) + requestIdSize(1) + vendorId(2) + vendorSerial(4)
    // + cmd(1) + sts(1) + tns(2) + func(1) = 18 bytes, no CM Unconnected Send wrapper.

    private static int GetFreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private static void WriteU16(byte[] buf, int offset, ushort value)
    {
        buf[offset] = (byte)(value & 0xFF);
        buf[offset + 1] = (byte)((value >> 8) & 0xFF);
    }

    private static void WriteU32(byte[] buf, int offset, uint value)
    {
        buf[offset] = (byte)(value & 0xFF);
        buf[offset + 1] = (byte)((value >> 8) & 0xFF);
        buf[offset + 2] = (byte)((value >> 16) & 0xFF);
        buf[offset + 3] = (byte)((value >> 24) & 0xFF);
    }

    private static ushort ReadU16(byte[] buf, int offset) => (ushort)(buf[offset] | (buf[offset + 1] << 8));

    private static async Task<byte[]> ReadExactAsync(NetworkStream stream, int count, int timeoutMs = 3000)
    {
        var buf = new byte[count];
        int total = 0;
        using var cts = new CancellationTokenSource(timeoutMs);
        while (total < count)
        {
            int n = await stream.ReadAsync(buf.AsMemory(total, count - total), cts.Token);
            if (n == 0) throw new IOException("Connection closed before the expected reply arrived.");
            total += n;
        }
        return buf;
    }

    private static async Task<byte[]> RegisterSessionAsync(NetworkStream stream)
    {
        byte[] req = new byte[28];
        WriteU16(req, 0, 0x0065);   // EIP_REGISTER_SESSION
        WriteU16(req, 2, 4);        // data length = 4
        WriteU16(req, 24, 1);       // requested transport version = 1
        WriteU16(req, 26, 0);       // options = 0
        await stream.WriteAsync(req);
        return await ReadExactAsync(stream, 28);
    }

    private static byte[] BuildDirectPcccRequest(byte cmd, byte sts, ushort tns, byte func)
    {
        var req = new byte[18];
        req[0] = 0x4B;                              // CIP_SERVICE_EXECUTE_PCCC
        req[1] = 0x02;                               // pathSize = 2 words
        req[2] = 0x20; req[3] = 0x67; req[4] = 0x24; req[5] = 0x01; // class 0x67 (PCCC object), instance 1
        req[6] = 0x07;                               // requestIdSize (fixed at 7 per spec)
        WriteU16(req, 7, 0x1234);                    // vendor id (arbitrary, echoed back verbatim)
        WriteU32(req, 9, 0x5678ABCD);                // vendor serial (arbitrary, echoed back verbatim)
        req[13] = cmd;
        req[14] = sts;
        WriteU16(req, 15, tns);
        req[17] = func;
        return req;
    }

    /// <summary>Wraps a direct Execute-PCCC request in a SendRRData (Unconnected Send) packet.</summary>
    private static byte[] BuildSendRRDataPacket(uint sessionHandle, byte[] pcccRequest)
    {
        int bodyLen = 4 + 2 + 2 + 4 + 4 + pcccRequest.Length;
        var packet = new byte[24 + bodyLen];

        WriteU16(packet, 0, 0x006F);              // command: SendRRData
        WriteU16(packet, 2, (ushort)bodyLen);     // length
        WriteU32(packet, 4, sessionHandle);       // session handle
        // status (8..11), sender context (12..19), options (20..23) all left as 0.

        int off = 24;
        WriteU32(packet, off, 0); off += 4;       // interface handle
        WriteU16(packet, off, 0); off += 2;       // timeout
        WriteU16(packet, off, 2); off += 2;       // item count = 2

        WriteU16(packet, off, 0x0000); off += 2;  // Null Address item: type
        WriteU16(packet, off, 0x0000); off += 2;  // Null Address item: length = 0

        WriteU16(packet, off, 0x00B2); off += 2;  // Unconnected Data item: type
        WriteU16(packet, off, (ushort)pcccRequest.Length); off += 2;
        Array.Copy(pcccRequest, 0, packet, off, pcccRequest.Length);

        return packet;
    }

    private static async Task WaitUntilAsync(Func<bool> condition, int timeoutMs)
    {
        var start = DateTime.UtcNow;
        while (!condition())
        {
            if ((DateTime.UtcNow - start).TotalMilliseconds > timeoutMs)
                throw new TimeoutException("Condition not met within timeout.");
            await Task.Delay(10);
        }
    }

    /// <summary>
    /// Minimal <see cref="ITransport"/> double standing in for the PLC link.
    /// Every <see cref="SendFrame"/> call is recorded, then answered — on a
    /// background task, like a real transport's own receive thread would —
    /// with a canned reply that echoes back the request's TNS and CMD|0x40,
    /// carrying <see cref="_replyData"/> as the response data.
    /// </summary>
    #pragma warning disable CS0067
    private sealed class FakePlcTransport : ITransport
    {
        private readonly byte[] _replyData;
        private readonly object _lock = new();

        public FakePlcTransport(byte[] replyData) => _replyData = replyData;

        public List<byte[]> SentFrames { get; } = new();

        public bool IsOpen { get; private set; }
        public event EventHandler<byte[]>? FrameReceived;
        public event EventHandler<byte[]>? RawFrameSent;
        public event EventHandler<byte[]>? RawFrameReceived;

        public void Open() => IsOpen = true;
        public void Close() => IsOpen = false;
        public void Dispose() => IsOpen = false;

        public void SendFrame(byte[] innerFrame)
        {
            lock (_lock) SentFrames.Add((byte[])innerFrame.Clone());

            byte cmd = innerFrame[2];
            byte tnsLo = innerFrame[4], tnsHi = innerFrame[5];

            var reply = new byte[6 + _replyData.Length];
            reply[2] = (byte)(cmd | 0x40); // AB PCCC reply convention: request CMD | 0x40
            reply[3] = 0x00;               // STS = success
            reply[4] = tnsLo;
            reply[5] = tnsHi;
            Array.Copy(_replyData, 0, reply, 6, _replyData.Length);

            _ = Task.Run(() => FrameReceived?.Invoke(this, reply));
        }
    }
    #pragma warning restore CS0067

    [Fact]
    public async Task ClientRequest_IsForwardedToPlc_AndReplyRoutedBackWithOriginalClientTns()
    {
        int port = GetFreePort();
        byte[] diagnosticPayload =
        {
            0x06, 0xEB, 0x4B, 0x00, 0x80, 0x01, 0x00, 0xA0,
            0xB8, 0xFD, 0x00, 0xC9, 0x00, 0x36, 0x00, 0x04,
        };
        var fakePlc = new FakePlcTransport(diagnosticPayload);
        var gateway = new Gateway(fakePlc, eipPort: port, bindAddress: IPAddress.Loopback);

        gateway.Start();
        try
        {
            // Wait for the link supervisor to open the PLC transport (and run its
            // own identity probe through the same fake) before driving a client
            // request through it.
            await WaitUntilAsync(() => fakePlc.IsOpen, 2000);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port);
            var stream = client.GetStream();

            byte[] registerResp = await RegisterSessionAsync(stream);
            uint sessionHandle = BitConverter.ToUInt32(registerResp, 4);

            const ushort clientTns = 0xABCD; // deliberately distinctive, unlikely to collide
                                              // with the gateway's own low, sequential TNS counter
            byte[] pcccReq = BuildDirectPcccRequest(cmd: 0x06, sts: 0x00, tns: clientTns, func: 0x03);
            byte[] packet = BuildSendRRDataPacket(sessionHandle, pcccReq);
            await stream.WriteAsync(packet);

            byte[] respHeader = await ReadExactAsync(stream, 24);
            ushort respCommand = ReadU16(respHeader, 0);
            ushort respLength = ReadU16(respHeader, 2);
            Assert.Equal((ushort)0x006F, respCommand);

            byte[] respBody = await ReadExactAsync(stream, respLength);

            // respBody: ifaceHandle(4) + timeout(2) + itemCount(2) + NullAddressItem(4)
            //           + UnconnectedDataItem header(4) + [Execute-PCCC reply payload]
            int off = 8;
            ushort item1Type = ReadU16(respBody, off);
            ushort item1Len = ReadU16(respBody, off + 2);
            Assert.Equal((ushort)0x0000, item1Type); // Null Address item
            off += 4 + item1Len;

            ushort item2Type = ReadU16(respBody, off);
            ushort item2Len = ReadU16(respBody, off + 2);
            off += 4;
            Assert.Equal((ushort)0x00B2, item2Type); // Unconnected Data item
            int item2PayloadStart = off;

            // Execute-PCCC reply header: 0xCB, reserved, generalStatus, addlStatusSize,
            // requestId(7), then the echoed PCCC cmd/sts/tns, then reply data.
            Assert.Equal((byte)0xCB, respBody[off]);
            Assert.Equal((byte)0x00, respBody[off + 2]); // general status = OK
            off += 4 + 7;

            byte replyCmd = respBody[off];
            byte replySts = respBody[off + 1];
            ushort replyTns = ReadU16(respBody, off + 2);
            off += 4;

            int dataLen = item2PayloadStart + item2Len - off;
            byte[] replyData = respBody[off..(off + dataLen)];

            Assert.Equal((byte)0x46, replyCmd);      // 0x06 | 0x40, from the fake PLC's canned reply
            Assert.Equal((byte)0x00, replySts);
            Assert.Equal(clientTns, replyTns);       // the client's OWN tns, not the gateway's internal one
            Assert.Equal(diagnosticPayload, replyData);

            // Confirm the frame that actually reached the "PLC" carried a DIFFERENT,
            // gateway-allocated TNS — i.e. the rewrite really happened, this isn't
            // just the client's TNS passing through untouched by coincidence.
            Assert.Contains(fakePlc.SentFrames,
                f => f.Length >= 6 && f[2] == 0x06 && ReadU16(f, 4) != clientTns);
        }
        finally
        {
            gateway.Stop();
        }
    }
}
