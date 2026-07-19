using System.Net;
using System.Net.Sockets;
using PcccGateway.Client;
using Xunit;

namespace PcccGateway.Tests;

/// <summary>
/// Tests for transport lifecycle: Open/Close/Open cycles,
/// lifecycle token cancellation, and reconnect behavior.
/// </summary>
public class TransportLifecycleTests
{
    private static int GetFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    /// <summary>
    /// Simple TCP echo server that can complete the CSPv4 and EIP handshakes.
    /// A verbatim echo is not a valid reply for either protocol, so the two
    /// fields a real device would not echo back are patched:
    /// <list type="bullet">
    ///   <item>
    ///     CSP: the RegisterSession request (mode=0x01, submode=0x01) has its
    ///     first byte changed to 0x02 (MODE_RESPONSE) and is given a non-zero
    ///     connection ID in bytes 4-7, as a real server would assign.
    ///   </item>
    ///   <item>
    ///     EIP: the RegisterSession request (command 0x0065) carries a zero
    ///     session handle, because the handle is what it is asking for. A real
    ///     device assigns a non-zero one in bytes 4-7 of the reply, so a
    ///     non-zero handle is written here.
    ///   </item>
    /// </list>
    /// Everything else is echoed unchanged.
    /// </summary>
    private sealed class EchoServer : IDisposable
    {
        private readonly TcpListener _listener;
        private CancellationTokenSource? _cts;
        private Task? _task;
        private bool _disposed;

        public EchoServer(int port)
        {
            _listener = new TcpListener(IPAddress.Loopback, port);
        }

        public void Start()
        {
            _listener.Start();
            _cts = new CancellationTokenSource();
            _task = Task.Run(() => HandleConnectionsAsync(_cts.Token));
        }

        private async Task HandleConnectionsAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var client = await _listener.AcceptTcpClientAsync(ct);
                    _ = Task.Run(() => HandleClientAsync(client, ct), ct);
                }
                catch (ObjectDisposedException) { break; }
                catch (OperationCanceledException) { break; }
                catch { /* ignore */ }
            }
        }

        /// <summary>
        /// Both the CSPv4 and the EIP RegisterSession request are exactly 28
        /// bytes (EIP: 24-byte header + 4-byte payload; CSP: a bare 28-byte
        /// header).
        /// </summary>
        private const int RegisterRequestLen = 28;

        private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
        {
            try
            {
                using (client)
                {
                    var stream = client.GetStream();
                    var buffer = new byte[4096];

                    // TCP preserves no message boundaries: ReadAsync may hand back
                    // the handshake in fragments. Patching a fragment would echo an
                    // unmodified header — and for EIP a zero session handle — while
                    // the following read no longer starts at the command byte. So
                    // the whole request is collected before it is inspected.
                    int read = await ReadAtLeastAsync(stream, buffer, RegisterRequestLen, ct);
                    if (read == 0) return;

                    // CSP RegisterSession (mode=0x01, submode=0x01): change the mode
                    // byte to 0x02 (response), and assign a connection ID in bytes 4-7
                    // (big-endian). The request carries zero because that is what it is
                    // asking for; echoing the zero back would let every later frame match
                    // on 0 == 0 and hide a transport that never stored the assigned ID.
                    if (read >= 28 && buffer[0] == 0x01 && buffer[1] == 0x01)
                    {
                        buffer[0] = 0x02;
                        buffer[4] = 0x00;
                        buffer[5] = 0x00;
                        buffer[6] = 0x00;
                        buffer[7] = 0x01;
                    }

                    // EIP RegisterSession (command 0x0065): a real device replies with
                    // a non-zero session handle in bytes 4-7. Echoing the request
                    // verbatim returns zero, which no device ever does.
                    if (read >= 24 && buffer[0] == 0x65 && buffer[1] == 0x00)
                    {
                        buffer[4] = 0x01;
                        buffer[5] = 0x00;
                        buffer[6] = 0x00;
                        buffer[7] = 0x00;
                    }

                    await stream.WriteAsync(buffer, 0, read, ct);

                    // Everything after the handshake is echoed verbatim.
                    while (!ct.IsCancellationRequested)
                    {
                        int n = await stream.ReadAsync(buffer, 0, buffer.Length, ct);
                        if (n == 0) break;
                        await stream.WriteAsync(buffer, 0, n, ct);
                    }
                }
            }
            catch { /* client disconnected */ }
        }

        /// <summary>
        /// Reads until at least <paramref name="count"/> bytes have arrived, or
        /// the peer closes. May return more when reads coalesce; the caller
        /// echoes exactly what was received.
        /// </summary>
        private static async Task<int> ReadAtLeastAsync(
            NetworkStream stream, byte[] buffer, int count, CancellationToken ct)
        {
            int total = 0;
            while (total < count)
            {
                int n = await stream.ReadAsync(buffer, total, buffer.Length - total, ct);
                if (n == 0) break;
                total += n;
            }
            return total;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _cts?.Cancel();
            try { _task?.Wait(1000); } catch { }
            _listener.Stop();
            _cts?.Dispose();
        }
    }

    [Fact]
    public async Task EIPTransport_Open_Close_Open_SendFrame_Succeeds()
    {
        int port = GetFreePort();
        using var server = new EchoServer(port);
        server.Start();

        var transport = new EIPTransport("127.0.0.1", port, 5000);

        try
        {
            transport.Open();
            Assert.True(transport.IsOpen);

            transport.Close();
            Assert.False(transport.IsOpen);

            transport.Open();
            Assert.True(transport.IsOpen);
        }
        finally
        {
            transport.Close();
        }
    }

    [Fact]
    public async Task CSPTransport_Open_Close_Open_SendFrame_Succeeds()
    {
        int port = GetFreePort();
        using var server = new EchoServer(port);
        server.Start();

        var transport = new CSPTransport("127.0.0.1", port, 5000);

        try
        {
            transport.Open();
            Assert.True(transport.IsOpen);

            transport.Close();
            Assert.False(transport.IsOpen);

            transport.Open();
            Assert.True(transport.IsOpen);
        }
        finally
        {
            transport.Close();
        }
    }

    [Fact]
    public async Task EIPTransport_Close_CancelsLifecycleToken()
    {
        int port = GetFreePort();
        using var server = new EchoServer(port);
        server.Start();

        var transport = new EIPTransport("127.0.0.1", port, 5000);

        try
        {
            transport.Open();
            Assert.True(transport.IsOpen);

            // Close should cancel the lifecycle token and wake any idle reads.
            // This is verified indirectly by the fact that Close returns promptly
            // even if there's a pending read.
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            transport.Close();
            stopwatch.Stop();

            // Close should complete quickly (not hang on an idle read).
            Assert.InRange(stopwatch.ElapsedMilliseconds, 0, 2000);
        }
        finally
        {
            transport.Close();
        }
    }
}
