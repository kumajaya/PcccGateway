using System.Net;
using System.Net.Sockets;
using PcccGateway.Common;
using PcccGateway.Server;
using Xunit;

namespace PcccGateway.Tests;

/// <summary>
/// Exercises <see cref="EIPServerTransport"/>'s handling of the encapsulation
/// header's Length field over a real loopback TCP socket. Deliberately does
/// NOT mock anything below the socket layer, since the bug this targets lives
/// in exactly that boundary: the 16-bit Length field is attacker/peer
/// controlled and is used to size a read into a fixed-capacity buffer before
/// any CIP-level parsing (which elsewhere in the file DOES bounds-check
/// diligently) ever gets a chance to run.
/// </summary>
public class EIPServerBoundaryTests : IDisposable
{
    private bool _disposed;

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

    [Fact]
    public async Task RegisterSession_HappyPath_Baseline()
    {
        int port = GetFreePort();
        var server = new EIPServerTransport(port, IPAddress.Loopback);
        server.Start();
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port);
            byte[] resp = await RegisterSessionAsync(client.GetStream());

            ushort respCommand = (ushort)(resp[0] | (resp[1] << 8));
            uint status = BitConverter.ToUInt32(resp, 8);
            Assert.Equal((ushort)0x0065, respCommand);
            Assert.Equal(0u, status);
        }
        finally
        {
            server.Stop();
        }
    }

    /// <summary>
    /// A client claims a Length field large enough that 24 (header) + Length
    /// exceeds the server's 65536-byte receive buffer. Nothing between the
    /// socket read and that buffer currently checks Length against the
    /// buffer's actual capacity before using it to size a read.
    /// <para>
    /// This test asserts the outcome that matters operationally: one
    /// malformed/hostile connection must not take down the listener or block
    /// other clients. It intentionally does NOT assert on exactly how the bad
    /// connection is terminated, because today that happens to be an
    /// unhandled <see cref="ArgumentException"/> from
    /// <c>Stream.ReadAsync</c> bubbling up through a generic catch — which
    /// works, but is accidental rather than a deliberate protocol-level
    /// rejection. See the accompanying review notes for the suggested fix.
    /// </para>
    /// </summary>
    [Fact]
    public async Task OversizedLengthField_DoesNotCrashListener_SubsequentClientStillServed()
    {
        int port = GetFreePort();
        var server = new EIPServerTransport(port, IPAddress.Loopback);
        server.Start();
        try
        {
            using (var badClient = new TcpClient())
            {
                await badClient.ConnectAsync(IPAddress.Loopback, port);
                byte[] header = new byte[24];
                WriteU16(header, 0, 0x0065);   // command is irrelevant; the bug triggers before dispatch
                WriteU16(header, 2, 0xFFF0);   // length = 65520 -> 24 + 65520 = 65544 > 65536-byte buffer
                await badClient.GetStream().WriteAsync(header);

                // Give the server a moment to process (and, today, fault on) this request.
                await Task.Delay(300);
            }

            // The listener — and its ability to serve OTHER clients — must survive.
            using var goodClient = new TcpClient();
            await goodClient.ConnectAsync(IPAddress.Loopback, port);
            byte[] resp = await RegisterSessionAsync(goodClient.GetStream());

            ushort respCommand = (ushort)(resp[0] | (resp[1] << 8));
            Assert.Equal((ushort)0x0065, respCommand);
        }
        finally
        {
            server.Stop();
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            // Ensure all pending log messages are flushed before the test runner
            // considers the test complete. We use a short delay instead of Logger.Shutdown()
            // to avoid terminating the static background writer thread required by other tests.
            Thread.Sleep(100);
            _disposed = true;
        }
    }
}
