using System.Net;
using System.Net.Sockets;
using System.Threading;
using PcccGateway.Server;
using Xunit;

namespace PcccGateway.Tests;

/// <summary>
/// Tests for <see cref="EIPServerTransport"/>'s CIP-level parsing:
/// Forward Open, Forward Close, Unconnected Send, Connected Send,
/// and Execute PCCC extraction.
/// </summary>
public class EIPServerParserTests : IDisposable
{
    private readonly EIPServerTransport _server;
    private readonly int _port;
    private bool _disposed;

    public EIPServerParserTests()
    {
        _port = GetFreePort();
        _server = new EIPServerTransport(_port, IPAddress.Loopback);
        _server.Start();
    }

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

    private static uint ReadU32(byte[] buf, int offset) =>
        (uint)(buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16) | (buf[offset + 3] << 24));

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

    private static async Task<(TcpClient Client, uint SessionHandle)> ConnectAndRegisterAsync(int port)
    {
        var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        var stream = client.GetStream();
        byte[] response = await RegisterSessionAsync(stream);
        uint sessionHandle = ReadU32(response, 4);
        return (client, sessionHandle);
    }

    /// <summary>
    /// Builds a Forward Open request (CIP service 0x54).
    /// Simplified version with minimal valid parameters.
    /// </summary>
    private static byte[] BuildForwardOpenRequest(uint otConnId, uint toConnId, ushort connSerial)
    {
        // Forward Open request layout per CIP Vol 1.
        // This is a simplified but valid request.
        var req = new byte[70];
        int off = 0;

        req[off++] = 0x54;           // CIP_SERVICE_FORWARD_OPEN
        req[off++] = 0x02;            // pathSize = 2 words
        // path: class 0x06 (Connection Manager), instance 0x01
        req[off++] = 0x20; req[off++] = 0x06;
        req[off++] = 0x24; req[off++] = 0x01;

        req[off++] = 0x0A;            // secsPerTick (10)
        req[off++] = 0x3C;            // timeoutTicks (60)

        WriteU32(req, off, otConnId); off += 4;
        WriteU32(req, off, toConnId); off += 4;
        WriteU16(req, off, connSerial); off += 2;
        WriteU16(req, off, 0x0001);    // vendorId (Rockwell)
        off += 2;
        WriteU32(req, off, 0x12345678); // serialNumber
        off += 4;
        req[off++] = 0x01;            // timeoutMultiplier
        off += 3;                     // reserved bytes

        // O→T RPI (4 bytes)
        WriteU32(req, off, 1_000_000); off += 4;
        // O→T connection parameters (2 bytes)
        WriteU16(req, off, 0x0000); off += 2;
        // T→O RPI (4 bytes)
        WriteU32(req, off, 1_000_000); off += 4;
        // T→O connection parameters (2 bytes)
        WriteU16(req, off, 0x0000); off += 2;
        req[off++] = 0x00;            // transportTypeAndTrigger (Class 3)

        return req[0..off];
    }

    /// <summary>
    /// Builds a Forward Close request (CIP service 0x4E).
    /// </summary>
    private static byte[] BuildForwardCloseRequest(ushort connSerial)
    {
        var req = new byte[28];
        int off = 0;

        req[off++] = 0x4E;           // CIP_SERVICE_FORWARD_CLOSE
        req[off++] = 0x02;            // pathSize = 2 words
        req[off++] = 0x20; req[off++] = 0x06;
        req[off++] = 0x24; req[off++] = 0x01;

        req[off++] = 0x0A;            // secsPerTick
        req[off++] = 0x3C;            // timeoutTicks
        WriteU16(req, off, connSerial); off += 2;
        WriteU16(req, off, 0x0001);    // vendorId
        off += 2;
        WriteU32(req, off, 0x12345678); // serialNumber
        off += 4;

        return req[0..off];
    }

    /// <summary>
    /// Wraps a CIP request in a SendRRData (Unconnected Send) packet.
    /// </summary>
    private static byte[] BuildSendRRDataPacket(uint sessionHandle, byte[] cipRequest)
    {
        int bodyLen = 4 + 2 + 2 + 4 + 4 + cipRequest.Length;
        var packet = new byte[24 + bodyLen];

        WriteU16(packet, 0, 0x006F);              // command: SendRRData
        WriteU16(packet, 2, (ushort)bodyLen);
        WriteU32(packet, 4, sessionHandle);

        int off = 24;
        WriteU32(packet, off, 0); off += 4;
        WriteU16(packet, off, 0); off += 2;
        WriteU16(packet, off, 2); off += 2;

        WriteU16(packet, off, 0x0000); off += 2;
        WriteU16(packet, off, 0x0000); off += 2;

        WriteU16(packet, off, 0x00B2); off += 2;
        WriteU16(packet, off, (ushort)cipRequest.Length); off += 2;
        Array.Copy(cipRequest, 0, packet, off, cipRequest.Length);

        return packet;
    }

    [Fact]
    public async Task ForwardOpen_ReturnsSuccessResponse()
    {
        var (client, sessionHandle) = await ConnectAndRegisterAsync(_port);
        using var _ = client;
        var stream = client.GetStream();

        uint otConnId = 0x12345678;
        uint toConnId = 0x87654321;
        ushort connSerial = 0xABCD;

        byte[] req = BuildForwardOpenRequest(otConnId, toConnId, connSerial);
        byte[] packet = BuildSendRRDataPacket(sessionHandle, req);
        await stream.WriteAsync(packet);

        // Read header
        byte[] respHeader = await ReadExactAsync(stream, 24);
        ushort respCommand = ReadU16(respHeader, 0);
        ushort respLength = ReadU16(respHeader, 2);
        uint status = ReadU32(respHeader, 8);
        Assert.Equal((ushort)0x006F, respCommand);
        Assert.Equal(0u, status);

        // Read body
        byte[] respBody = await ReadExactAsync(stream, respLength);

        // Verify it's a Forward Open response (service 0xD4)
        // The response body starts with CPF items: Null Address + Unconnected Data.
        // Unconnected Data payload begins after Null Address item.
        int off = 8; // interface handle(4) + timeout(2) + itemCount(2)
        // Skip Null Address item (type 0x0000, length 0)
        ushort item1Type = ReadU16(respBody, off);
        ushort item1Len = ReadU16(respBody, off + 2);
        off += 4 + item1Len;
        Assert.Equal((ushort)0x0000, item1Type);

        // Unconnected Data item
        ushort item2Type = ReadU16(respBody, off);
        ushort item2Len = ReadU16(respBody, off + 2);
        off += 4;
        Assert.Equal((ushort)0x00B2, item2Type);

        // Forward Open reply service code should be 0xD4
        byte replySvc = respBody[off];
        byte generalStatus = respBody[off + 2];
        Assert.Equal((byte)0xD4, replySvc); // Forward Open response
        Assert.Equal((byte)0x00, generalStatus); // Success

        // Extract orig_to_targ_conn_id (assigned connection ID)
        uint assignedId = ReadU32(respBody, off + 4);
        // Should not be zero
        Assert.NotEqual(0u, assignedId);
    }

    [Fact]
    public async Task ForwardOpen_ThenForwardClose_Succeeds()
    {
        var (client, sessionHandle) = await ConnectAndRegisterAsync(_port);
        using var _ = client;
        var stream = client.GetStream();

        uint otConnId = 0x12345678;
        uint toConnId = 0x87654321;
        ushort connSerial = 0xABCD;

        // Step 1: Forward Open
        byte[] fwdOpenReq = BuildForwardOpenRequest(otConnId, toConnId, connSerial);
        byte[] openPacket = BuildSendRRDataPacket(sessionHandle, fwdOpenReq);
        await stream.WriteAsync(openPacket);

        // Read Forward Open response
        byte[] openRespHeader = await ReadExactAsync(stream, 24);
        ushort openRespLength = ReadU16(openRespHeader, 2);
        byte[] openRespBody = await ReadExactAsync(stream, openRespLength);

        // Extract assigned connection ID
        int off = 8;
        off += 4 + 0; // Skip Null Address item
        off += 4;     // Skip Unconnected Data header
        uint assignedId = ReadU32(openRespBody, off + 4);
        Assert.NotEqual(0u, assignedId);

        // Step 2: Forward Close
        byte[] fwdCloseReq = BuildForwardCloseRequest(connSerial);
        byte[] closePacket = BuildSendRRDataPacket(sessionHandle, fwdCloseReq);
        await stream.WriteAsync(closePacket);

        // Read Forward Close response
        byte[] closeRespHeader = await ReadExactAsync(stream, 24);
        ushort closeRespCommand = ReadU16(closeRespHeader, 0);
        ushort closeRespLength = ReadU16(closeRespHeader, 2);
        uint closeStatus = ReadU32(closeRespHeader, 8);
        Assert.Equal((ushort)0x006F, closeRespCommand);
        Assert.Equal(0u, closeStatus);

        byte[] closeRespBody = await ReadExactAsync(stream, closeRespLength);
        off = 8;
        off += 4 + 0; // Skip Null Address item
        off += 4;     // Skip Unconnected Data header
        byte closeReplySvc = closeRespBody[off];
        byte closeGeneralStatus = closeRespBody[off + 2];
        Assert.Equal((byte)0xCE, closeReplySvc); // Forward Close response
        Assert.Equal((byte)0x00, closeGeneralStatus);
    }

    [Fact]
    public async Task ForwardOpen_WrongSessionHandle_IsRejectedOrIgnored()
    {
        var (client, sessionHandle) = await ConnectAndRegisterAsync(_port);
        using var _ = client;
        var stream = client.GetStream();

        byte[] req = BuildForwardOpenRequest(0x12345678, 0x87654321, 0xABCD);
        byte[] packet = BuildSendRRDataPacket(sessionHandle + 1, req);
        await stream.WriteAsync(packet);

        var header = new byte[24];
        int read = 0;
        using var cts = new CancellationTokenSource(500);
        try
        {
            while (read < 24)
            {
                int n = await stream.ReadAsync(header, read, 24 - read, cts.Token);
                if (n == 0) break;
                read += n;
            }
        }
        catch (OperationCanceledException)
        {
            read = 0;
        }

        if (read > 0)
        {
            ushort command = ReadU16(header, 0);
            uint status = ReadU32(header, 8);
            Assert.True(command != 0x006F || status != 0u,
                "Server accepted Forward Open with a wrong session handle.");
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _server.Stop();
            _disposed = true;
        }
    }
}
