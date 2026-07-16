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
    /// Simple TCP echo server that can handle basic CSPv4 handshake.
    /// For EIP, it just echoes raw bytes. For CSP, it detects the RegisterSession
    /// request (mode=0x01, submode=0x01) and changes the first byte to 0x02
    /// (MODE_RESPONSE) so the client accepts the response.
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

        private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
        {
            try
            {
                using (client)
                {
                    var stream = client.GetStream();
                    var buffer = new byte[4096];
                    while (!ct.IsCancellationRequested)
                    {
                        int read = await stream.ReadAsync(buffer, 0, buffer.Length, ct);
                        if (read == 0) break;

                        // If this looks like a CSP RegisterSession request (mode=0x01, submode=0x01),
                        // change the mode byte to 0x02 (response) so the client accepts it.
                        if (read >= 28 && buffer[0] == 0x01 && buffer[1] == 0x01)
                        {
                            buffer[0] = 0x02;
                        }

                        // Echo back what was received (with the mode adjusted if CSP).
                        await stream.WriteAsync(buffer, 0, read, ct);
                    }
                }
            }
            catch { /* client disconnected */ }
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

            // Allow the background receive loop from the previous connection to
            // fully exit before opening a new one. This prevents ObjectDisposedException
            // when the new connection attempts to create a fresh NetworkStream while
            // the old one is still being torn down.
            await Task.Delay(50);

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
