using System.Net;
using System.Net.Sockets;
using PcccGateway.Client;
using PcccGateway.Interface;
using Xunit;

namespace PcccGateway.Tests;

/// <summary>
/// Tests for the shared TCP transport machinery in <see cref="TCPBaseTransport"/>,
/// exercised through its two concrete subclasses.
///
/// The fake device below frames each protocol properly rather than echoing raw
/// bytes, so a coalesced or fragmented read cannot silently turn into a
/// malformed reply and a confusing test failure.
/// </summary>
public class TCPBaseTransportTests
{
    private const int SignalTimeoutMs = 3000;

    // Structural limits, mirrored here because the members are protected. These
    // are what each encapsulation's 16-bit length field can express — NOT a PCCC
    // content limit. The transports deliberately impose none: judging whether a
    // payload is acceptable belongs to the PLC, which answers with a status code.
    private const int EipMaxInnerFrame = 65508;   // 16-bit length covers 27 + inner
    private const int CspMaxInnerFrame = 65533;   // 16-bit data_length covers inner + 2
    private const int MinInnerFrame = 2;          // DST + SRC, what the builders split

    private static int GetFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    /// <summary>
    /// A minimal CSPv4 / EtherNet-IP device.
    ///
    /// Completes the registration handshake, then reflects each PCCC request
    /// back as a well-formed response. Reflection is enough to drive the
    /// receive path end to end: an EIP Execute PCCC request (service 0x4B)
    /// reflected verbatim still satisfies the client's own parser, and a CSP
    /// request only needs its mode byte flipped to 0x02.
    /// </summary>
    private sealed class FakeDevice : IDisposable
    {
        private readonly TcpListener _listener;
        private CancellationTokenSource? _cts;
        private Task? _task;
        private bool _disposed;

        /// <summary>Session handle / connection ID handed out at registration.</summary>
        public uint SessionIdToAssign { get; init; } = 1;

        /// <summary>Counts UnregisterSession requests (EIP command 0x0066).</summary>
        public int UnregisterCount;

        public FakeDevice(int port) => _listener = new TcpListener(IPAddress.Loopback, port);

        public void Start()
        {
            _listener.Start();
            _cts = new CancellationTokenSource();
            _task = Task.Run(() => AcceptLoopAsync(_cts.Token));
        }

        private async Task AcceptLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var client = await _listener.AcceptTcpClientAsync(ct);
                    _ = Task.Run(() => ServeAsync(client, ct), ct);
                }
                catch (ObjectDisposedException) { break; }
                catch (OperationCanceledException) { break; }
                catch { /* keep accepting */ }
            }
        }

        private async Task ServeAsync(TcpClient client, CancellationToken ct)
        {
            try
            {
                using (client)
                {
                    var stream = client.GetStream();

                    // ── Registration ────────────────────────────────────────
                    // Both register requests are 28 bytes: CSP is a bare header,
                    // EIP is a 24-byte header plus a 4-byte payload.
                    byte[] reg = new byte[28];
                    if (!await ReadExactAsync(stream, reg, 0, 28, ct)) return;

                    bool isCsp = reg[0] == 0x01 && reg[1] == 0x01;

                    if (isCsp)
                    {
                        reg[0] = 0x02;                                   // MODE_RESPONSE
                        WriteUInt32BE(reg, 4, SessionIdToAssign);        // conn ID (big-endian)
                        await stream.WriteAsync(reg.AsMemory(0, 28), ct);
                        await ServeCspAsync(stream, ct);
                    }
                    else
                    {
                        BitConverter.GetBytes(SessionIdToAssign).CopyTo(reg, 4); // little-endian
                        await stream.WriteAsync(reg.AsMemory(0, 28), ct);
                        await ServeEipAsync(stream, ct);
                    }
                }
            }
            catch { /* client went away */ }
        }

        private async Task ServeCspAsync(NetworkStream stream, CancellationToken ct)
        {
            byte[] header = new byte[28];
            while (!ct.IsCancellationRequested)
            {
                if (!await ReadExactAsync(stream, header, 0, 28, ct)) return;

                int dataLen = (header[2] << 8) | header[3];
                byte[] payload = new byte[dataLen];
                if (dataLen > 0 && !await ReadExactAsync(stream, payload, 0, dataLen, ct)) return;

                header[0] = 0x02;   // request -> response; everything else reflects
                await stream.WriteAsync(header.AsMemory(0, 28), ct);
                if (dataLen > 0) await stream.WriteAsync(payload.AsMemory(0, dataLen), ct);
            }
        }

        private async Task ServeEipAsync(NetworkStream stream, CancellationToken ct)
        {
            byte[] header = new byte[24];
            while (!ct.IsCancellationRequested)
            {
                if (!await ReadExactAsync(stream, header, 0, 24, ct)) return;

                int dataLen = BitConverter.ToUInt16(header, 2);
                byte[] payload = new byte[dataLen];
                if (dataLen > 0 && !await ReadExactAsync(stream, payload, 0, dataLen, ct)) return;

                ushort command = BitConverter.ToUInt16(header, 0);
                if (command == 0x0066)        // UnregisterSession — no reply
                {
                    Interlocked.Increment(ref UnregisterCount);
                    continue;
                }

                await stream.WriteAsync(header.AsMemory(0, 24), ct);
                if (dataLen > 0) await stream.WriteAsync(payload.AsMemory(0, dataLen), ct);
            }
        }

        private static async Task<bool> ReadExactAsync(
            NetworkStream stream, byte[] buffer, int offset, int count, CancellationToken ct)
        {
            int total = 0;
            while (total < count)
            {
                int n = await stream.ReadAsync(buffer.AsMemory(offset + total, count - total), ct);
                if (n == 0) return false;
                total += n;
            }
            return true;
        }

        private static void WriteUInt32BE(byte[] buf, int offset, uint value)
        {
            buf[offset] = (byte)(value >> 24);
            buf[offset + 1] = (byte)(value >> 16);
            buf[offset + 2] = (byte)(value >> 8);
            buf[offset + 3] = (byte)(value & 0xFF);
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

    /// <summary>A minimal well-formed inner frame: DST, SRC, CMD, STS, TNS.</summary>
    private static byte[] InnerFrame(byte dst = 0x01, byte src = 0x00, ushort tns = 0x1234) =>
        new byte[] { dst, src, 0x0F, 0x00, (byte)(tns & 0xFF), (byte)(tns >> 8) };

    // ─── SendFrame argument validation ───────────────────────────────────────
    //
    // Validation runs before the transport-open check, so these need no socket.
    // "Transport is not open" is therefore the signal that a length was ACCEPTED.

    [Fact]
    public void SendFrame_NullFrame_Throws()
    {
        using var transport = new EIPTransport("127.0.0.1", 44818);
        Assert.Throws<ArgumentNullException>(() => transport.SendFrame(null!));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(MinInnerFrame - 1)]
    public void SendFrame_BelowTheStructuralMinimum_Throws(int length)
    {
        // Under two bytes the packet builders cannot split DST/SRC off without
        // computing a negative payload length.
        using var transport = new EIPTransport("127.0.0.1", 44818);
        Assert.Throws<ArgumentException>(() => transport.SendFrame(new byte[length]));
    }

    [Theory]
    [InlineData("eip", EipMaxInnerFrame + 1)]
    [InlineData("csp", CspMaxInnerFrame + 1)]
    public void SendFrame_AboveTheEncapsulationMaximum_Throws(string protocol, int length)
    {
        // One past the largest inner frame the 16-bit length field can hold.
        // Beyond it the field wraps and the packet on the wire is malformed —
        // a mechanical failure, not a protocol opinion.
        using ITransport transport = Create(protocol, 44818);
        Assert.Throws<ArgumentOutOfRangeException>(() => transport.SendFrame(new byte[length]));
    }

    [Theory]
    [InlineData("eip", EipMaxInnerFrame)]
    [InlineData("csp", CspMaxInnerFrame)]
    public void SendFrame_AtTheEncapsulationMaximum_IsAccepted(string protocol, int length)
    {
        // Pins the exact ceiling from below. Without this, the rejection tests
        // above would stay green if a limit were accidentally lowered — they only
        // prove that SOME value is rejected, not which. Accepted by validation, so
        // the failure that surfaces is the closed transport.
        using ITransport transport = Create(protocol, 44818);
        Assert.Throws<InvalidOperationException>(() => transport.SendFrame(new byte[length]));
    }

    [Fact]
    public void SendFrame_PastTheFormerPcccCeiling_IsAccepted()
    {
        // 251 bytes was rejected by a PCCC content limit this transport no longer
        // imposes. Validation now passes it, so the failure that surfaces is the
        // closed transport — which is what proves the length check is gone.
        using var transport = new EIPTransport("127.0.0.1", 44818);
        Assert.Throws<InvalidOperationException>(() => transport.SendFrame(new byte[251]));
    }

    [Theory]
    [InlineData(6)]
    [InlineData(250)]
    [InlineData(512)]
    public async Task SendFrame_SurvivesTheEncapsulation_AtVariousSizes(int length)
    {
        // 512 is the one that matters: both the outbound check and the inbound
        // discard used to reject it, so a frame this size could not previously
        // complete a round trip in either direction.
        //
        // Sent to a live device rather than asserting "transport is not open" on a
        // closed one. That earlier form passed only because validation happens to
        // run before the open check: reordering the two would have kept it green
        // while it quietly stopped testing anything.
        int port = GetFreePort();
        using var device = new FakeDevice(port);
        device.Start();

        using var transport = new EIPTransport("127.0.0.1", port, 5000);
        var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        transport.FrameReceived += (_, f) => received.TrySetResult(f);

        byte[] frame = InnerFrame();
        Array.Resize(ref frame, length);
        for (int i = 6; i < length; i++)
            frame[i] = (byte)i;   // distinct payload, so a truncated round trip shows up

        transport.Open();
        transport.SendFrame(frame);   // must not throw at either boundary

        byte[] echoed = await AwaitSignalAsync(received.Task, "FrameReceived was never raised.");
        Assert.Equal(frame, echoed);
    }

    // ─── Lifecycle ───────────────────────────────────────────────────────────

    [Fact]
    public void Close_BeforeOpen_IsNoOp()
    {
        using var transport = new EIPTransport("127.0.0.1", 44818);
        transport.Close();                 // must not throw
        Assert.False(transport.IsOpen);
    }

    [Fact]
    public void Open_AfterDispose_Throws()
    {
        var transport = new EIPTransport("127.0.0.1", 44818);
        transport.Dispose();
        Assert.Throws<ObjectDisposedException>(() => transport.Open());
    }

    [Fact]
    public void Dispose_Twice_IsSafe()
    {
        var transport = new EIPTransport("127.0.0.1", 44818);
        transport.Dispose();
        transport.Dispose();
    }

    [Theory]
    [InlineData("eip")]
    [InlineData("csp")]
    public void Close_Twice_IsIdempotent(string protocol)
    {
        int port = GetFreePort();
        using var device = new FakeDevice(port);
        device.Start();

        using ITransport transport = Create(protocol, port);
        transport.Open();
        Assert.True(transport.IsOpen);

        transport.Close();
        transport.Close();
        Assert.False(transport.IsOpen);
    }

    [Theory]
    [InlineData("eip")]
    [InlineData("csp")]
    public void OpenCloseOpen_ReusesTheTransport(string protocol)
    {
        int port = GetFreePort();
        using var device = new FakeDevice(port);
        device.Start();

        using ITransport transport = Create(protocol, port);

        transport.Open();
        Assert.True(transport.IsOpen);
        transport.Close();
        Assert.False(transport.IsOpen);
        transport.Open();
        Assert.True(transport.IsOpen);
    }

    [Theory]
    [InlineData("eip")]
    [InlineData("csp")]
    public void Close_OnHealthyConnection_ReturnsPromptly(string protocol)
    {
        // The receive loop is parked in ReadAsync on an idle connection. Close()
        // must cancel it rather than wait out ReceiveLoopDrainTimeoutMs (1000 ms),
        // so the bound has to sit well below that to mean anything.
        int port = GetFreePort();
        using var device = new FakeDevice(port);
        device.Start();

        using ITransport transport = Create(protocol, port);
        transport.Open();

        var sw = System.Diagnostics.Stopwatch.StartNew();
        transport.Close();
        sw.Stop();

        Assert.InRange(sw.ElapsedMilliseconds, 0, 500);
    }

    // ─── Registration ────────────────────────────────────────────────────────

    [Theory]
    [InlineData("eip")]
    [InlineData("csp")]
    public void Open_WhenDeviceAssignsZeroSessionId_Fails(string protocol)
    {
        int port = GetFreePort();
        using var device = new FakeDevice(port) { SessionIdToAssign = 0 };
        device.Start();

        using ITransport transport = Create(protocol, port);

        var ex = Assert.Throws<InvalidOperationException>(() => transport.Open());
        Assert.IsType<InvalidDataException>(ex.InnerException);
        Assert.False(transport.IsOpen);
    }

    [Fact]
    public void Close_SendsUnregisterSession_OnEip()
    {
        int port = GetFreePort();
        using var device = new FakeDevice(port);
        device.Start();

        using var transport = new EIPTransport("127.0.0.1", port, 5000);
        transport.Open();
        transport.Close();

        Assert.True(SpinWait(() => Volatile.Read(ref device.UnregisterCount) == 1));
    }

    // ─── Receive path ────────────────────────────────────────────────────────

    [Theory]
    [InlineData("eip")]
    [InlineData("csp")]
    public async Task SendFrame_ReflectedByDevice_RaisesFrameReceived(string protocol)
    {
        int port = GetFreePort();
        using var device = new FakeDevice(port);
        device.Start();

        using ITransport transport = Create(protocol, port);
        var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        transport.FrameReceived += (_, f) => received.TrySetResult(f);

        transport.Open();
        transport.SendFrame(InnerFrame(tns: 0x1234));

        byte[] frame = await AwaitSignalAsync(received.Task, "FrameReceived was never raised.");

        // PCCC content survives the round trip intact. DST/SRC are asserted
        // separately: CSP carries them in the LSAP, while EIP has no place for
        // them and substitutes 0x01/0x00 on the way back in.
        Assert.Equal(6, frame.Length);
        Assert.Equal(0x0F, frame[2]);        // CMD
        Assert.Equal(0x00, frame[3]);        // STS
        Assert.Equal(0x34, frame[4]);        // TNS low
        Assert.Equal(0x12, frame[5]);        // TNS high
    }

    [Fact]
    public async Task CspTransport_PreservesDstAndSrc_AcrossTheRoundTrip()
    {
        int port = GetFreePort();
        using var device = new FakeDevice(port);
        device.Start();

        using var transport = new CSPTransport("127.0.0.1", port, 5000);
        var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        transport.FrameReceived += (_, f) => received.TrySetResult(f);

        transport.Open();
        transport.SendFrame(InnerFrame(dst: 0x09, src: 0x05));

        byte[] frame = await AwaitSignalAsync(received.Task, "FrameReceived was never raised.");
        Assert.Equal(0x09, frame[0]);
        Assert.Equal(0x05, frame[1]);
    }

    [Fact]
    public async Task RawFrameReceived_IsRaisedBefore_FrameReceived()
    {
        int port = GetFreePort();
        using var device = new FakeDevice(port);
        device.Start();

        using var transport = new EIPTransport("127.0.0.1", port, 5000);

        var order = new List<string>();
        var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        transport.RawFrameReceived += (_, _) => { lock (order) order.Add("raw"); };
        transport.FrameReceived += (_, _) =>
        {
            lock (order) order.Add("decoded");
            done.TrySetResult(true);
        };

        transport.Open();
        transport.SendFrame(InnerFrame());

        await AwaitSignalAsync(done.Task, "FrameReceived was never raised.");
        lock (order)
            Assert.Equal(new[] { "raw", "decoded" }, order);
    }

    [Fact]
    public void RawFrameSent_IsRaised_AfterTheBytesReachTheWire()
    {
        int port = GetFreePort();
        using var device = new FakeDevice(port);
        device.Start();

        using var transport = new EIPTransport("127.0.0.1", port, 5000);
        byte[]? sent = null;
        transport.RawFrameSent += (_, p) => sent = p;

        transport.Open();
        transport.SendFrame(InnerFrame());

        Assert.NotNull(sent);
        Assert.True(sent!.Length > 24, "The raw packet should include the encapsulation header.");
    }

    // ─── Subscriber isolation ────────────────────────────────────────────────

    [Fact]
    public async Task ThrowingFrameReceivedHandler_DoesNotTearDownTheConnection()
    {
        // Before the refactor a throwing handler propagated into the receive
        // loop's catch-all and silently killed the session.
        int port = GetFreePort();
        using var device = new FakeDevice(port);
        device.Start();

        using var transport = new EIPTransport("127.0.0.1", port, 5000);

        int deliveries = 0;
        var second = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        transport.FrameReceived += (_, _) =>
        {
            if (Interlocked.Increment(ref deliveries) == 2) second.TrySetResult(true);
            throw new InvalidOperationException("subscriber blew up");
        };

        transport.Open();
        transport.SendFrame(InnerFrame(tns: 0x0001));
        transport.SendFrame(InnerFrame(tns: 0x0002));

        await AwaitSignalAsync(second.Task,
            "The second frame was not delivered — the first handler's exception killed the loop.");
        Assert.True(transport.IsOpen);
    }

    [Fact]
    public void RawFrameSent_IsRaisedOutside_TheSendLock()
    {
        // The base class documents that RawFrameSent is raised outside _sendLock
        // "so a subscriber may safely re-enter the transport".
        //
        // A handler that re-enters on its OWN thread proves nothing: lock in C# is
        // Monitor, which is re-entrant per thread, so that send would succeed
        // whether or not the lock is held. A SECOND thread is what discriminates.
        // If the event were raised while _sendLock is held, the send below would
        // block until the handler returns — and the handler is waiting on it.
        int port = GetFreePort();
        using var device = new FakeDevice(port);
        device.Start();

        using var transport = new EIPTransport("127.0.0.1", port, 5000);

        int depth = 0;
        bool reentrantSendCompleted = false;
        using var secondDone = new ManualResetEventSlim(false);

        transport.RawFrameSent += (s, _) =>
        {
            // The nested send raises this event again; only the outer one recurses.
            if (Interlocked.Increment(ref depth) != 1) return;

            ThreadPool.QueueUserWorkItem(_ =>
            {
                try { ((ITransport)s!).SendFrame(InnerFrame(tns: 0x0002)); }
                catch { /* surfaced through the flag below */ }
                finally { secondDone.Set(); }
            });

            reentrantSendCompleted = secondDone.Wait(1000);
        };

        transport.Open();
        transport.SendFrame(InnerFrame(tns: 0x0001));

        Assert.True(reentrantSendCompleted,
            "A send from another thread blocked while a RawFrameSent handler was running — " +
            "the event appears to be raised while _sendLock is held.");
        Assert.True(transport.IsOpen);
    }

    [Fact]
    public void ThrowingRawFrameSentHandler_DoesNotFailSendFrame()
    {
        // A transmission that reached the wire must not be reported as failed:
        // the caller would retry and duplicate the request.
        int port = GetFreePort();
        using var device = new FakeDevice(port);
        device.Start();

        using var transport = new EIPTransport("127.0.0.1", port, 5000);
        transport.RawFrameSent += (_, _) => throw new InvalidOperationException("subscriber blew up");

        transport.Open();
        transport.SendFrame(InnerFrame());     // must not throw

        Assert.True(transport.IsOpen);
    }

    // ─── Teardown from inside a receive callback ─────────────────────────────

    [Fact]
    public async Task Close_CalledFromInsideAFrameReceivedHandler_DoesNotHang()
    {
        // The handler runs ON the receive loop. Without the per-thread marker in
        // the base class, Close() would wait for the very loop it is standing on
        // and burn the full drain timeout.
        int port = GetFreePort();
        using var device = new FakeDevice(port);
        device.Start();

        using var transport = new EIPTransport("127.0.0.1", port, 5000);

        var closed = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);
        transport.FrameReceived += (s, _) =>
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            ((ITransport)s!).Close();
            sw.Stop();
            closed.TrySetResult(sw.ElapsedMilliseconds);
        };

        transport.Open();
        transport.SendFrame(InnerFrame());

        long elapsedMs = await AwaitSignalAsync(closed.Task, "The handler never completed its Close().");
        Assert.InRange(elapsedMs, 0, 500);
        Assert.False(transport.IsOpen);
    }

    [Fact]
    public async Task Dispose_CalledFromInsideAFrameReceivedHandler_DoesNotHang()
    {
        int port = GetFreePort();
        using var device = new FakeDevice(port);
        device.Start();

        var transport = new EIPTransport("127.0.0.1", port, 5000);

        var disposed = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);
        transport.FrameReceived += (s, _) =>
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            ((IDisposable)s!).Dispose();
            sw.Stop();
            disposed.TrySetResult(sw.ElapsedMilliseconds);
        };

        transport.Open();
        transport.SendFrame(InnerFrame());

        long elapsedMs = await AwaitSignalAsync(disposed.Task, "The handler never completed its Dispose().");
        Assert.InRange(elapsedMs, 0, 500);
    }

    // ─── Send on a closed transport ──────────────────────────────────────────

    [Theory]
    [InlineData("eip")]
    [InlineData("csp")]
    public void SendFrame_AfterClose_Throws(string protocol)
    {
        int port = GetFreePort();
        using var device = new FakeDevice(port);
        device.Start();

        using ITransport transport = Create(protocol, port);
        transport.Open();
        transport.Close();

        Assert.Throws<InvalidOperationException>(() => transport.SendFrame(InnerFrame()));
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private static ITransport Create(string protocol, int port) => protocol switch
    {
        "eip" => new EIPTransport("127.0.0.1", port, 5000),
        "csp" => new CSPTransport("127.0.0.1", port, 5000),
        _ => throw new ArgumentOutOfRangeException(nameof(protocol))
    };

    /// <summary>
    /// Awaits a signal with a deadline, reporting a timeout as a readable test
    /// failure rather than a bare TimeoutException. Used instead of
    /// <c>Task.Wait(ms)</c>, which trips xUnit1031.
    /// </summary>
    private static async Task<T> AwaitSignalAsync<T>(Task<T> task, string whatWasExpected)
    {
        try
        {
            return await task.WaitAsync(TimeSpan.FromMilliseconds(SignalTimeoutMs));
        }
        catch (TimeoutException)
        {
            Assert.Fail(whatWasExpected);
            throw;   // unreachable: Assert.Fail always throws
        }
    }

    private static bool SpinWait(Func<bool> condition, int timeoutMs = SignalTimeoutMs)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            if (condition()) return true;
            Thread.Sleep(10);
        }
        return condition();
    }
}
