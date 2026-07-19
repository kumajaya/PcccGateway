using PcccGateway.Client;
using Xunit;

namespace PcccGateway.Tests;

/// <summary>
/// Tests for <see cref="SerialPortWrapper"/>'s session lifecycle: generation
/// tagging, the callback lease, teardown from inside a handler, and receive
/// queue overflow recovery.
///
/// Ordering of delivered chunks is covered by <see cref="SerialPortWrapperTests"/>;
/// this file is about what happens around Open/Close/Dispose.
/// </summary>
public class SerialPortWrapperSessionTests
{
    private const int WaitMs = 3000;

    // ─── Session gating ──────────────────────────────────────────────────────

    [Fact]
    public void ChunksArrivingBeforeOpen_AreIgnored()
    {
        var port = new FakeSerialPort();
        using var wrapper = new SerialPortWrapper(port);

        int delivered = 0;
        wrapper.BytesReceived += (_, _) => Interlocked.Increment(ref delivered);

        port.SimulateReceive(new byte[] { 0x01 });   // no session yet

        Thread.Sleep(150);
        Assert.Equal(0, Volatile.Read(ref delivered));
    }

    [Fact]
    public void ChunksArrivingAfterClose_AreNotDelivered()
    {
        var port = new FakeSerialPort();
        using var wrapper = new SerialPortWrapper(port);
        wrapper.Open();

        var first = new ManualResetEventSlim(false);
        int delivered = 0;
        wrapper.BytesReceived += (_, _) =>
        {
            Interlocked.Increment(ref delivered);
            first.Set();
        };

        port.SimulateReceive(new byte[] { 0x01 });
        Assert.True(first.Wait(WaitMs));

        wrapper.Close();
        port.SimulateReceive(new byte[] { 0x02 });

        Thread.Sleep(150);
        Assert.Equal(1, Volatile.Read(ref delivered));
    }

    [Fact]
    public void ChunkIsCloned_SoALaterMutationByTheProducerIsNotSeen()
    {
        // OnBytesReceived clones before queuing, because an ISerialPort is only
        // required to keep the buffer valid for its synchronous call.
        var port = new FakeSerialPort();
        using var wrapper = new SerialPortWrapper(port);
        wrapper.Open();

        byte[]? seen = null;
        var got = new ManualResetEventSlim(false);
        wrapper.BytesReceived += (_, c) => { seen = c; got.Set(); };

        var shared = new byte[] { 0xAA, 0xBB };
        port.SimulateReceive(shared);
        shared[0] = 0xFF;                    // producer reuses its buffer

        Assert.True(got.Wait(WaitMs));
        Assert.Equal(new byte[] { 0xAA, 0xBB }, seen);
    }

    // ─── Lifecycle guards ────────────────────────────────────────────────────

    [Fact]
    public void Open_AfterDispose_Throws()
    {
        var port = new FakeSerialPort();
        var wrapper = new SerialPortWrapper(port);
        wrapper.Dispose();

        Assert.Throws<ObjectDisposedException>(() => wrapper.Open());
    }

    [Fact]
    public void Write_WhenClosed_Throws()
    {
        var port = new FakeSerialPort();
        using var wrapper = new SerialPortWrapper(port);

        Assert.Throws<InvalidOperationException>(() => wrapper.Write(new byte[] { 1 }, 0, 1));
    }

    [Fact]
    public void Write_AfterDispose_Throws()
    {
        var port = new FakeSerialPort();
        var wrapper = new SerialPortWrapper(port);
        wrapper.Open();
        wrapper.Dispose();

        Assert.Throws<ObjectDisposedException>(() => wrapper.Write(new byte[] { 1 }, 0, 1));
    }

    [Fact]
    public void CloseTwice_And_DisposeTwice_AreIdempotent()
    {
        var port = new FakeSerialPort();
        var wrapper = new SerialPortWrapper(port);

        wrapper.Open();
        wrapper.Close();
        wrapper.Close();
        Assert.False(wrapper.IsOpen);

        wrapper.Dispose();
        wrapper.Dispose();
    }

    [Fact]
    public void OpenCloseOpen_StartsAFreshSession()
    {
        var port = new FakeSerialPort();
        using var wrapper = new SerialPortWrapper(port);

        int delivered = 0;
        var got = new ManualResetEventSlim(false);
        wrapper.BytesReceived += (_, _) =>
        {
            Interlocked.Increment(ref delivered);
            got.Set();
        };

        wrapper.Open();
        wrapper.Close();
        wrapper.Open();
        Assert.True(wrapper.IsOpen);

        port.SimulateReceive(new byte[] { 0x42 });
        Assert.True(got.Wait(WaitMs));
        Assert.Equal(1, Volatile.Read(ref delivered));
    }

    // ─── Teardown from inside a handler ──────────────────────────────────────

    [Fact]
    public void Close_CalledFromInsideAHandler_DoesNotDeadlock()
    {
        // The handler runs on the callback consumer. WaitForCallbackLease() must
        // notice it is on that very thread and return instead of waiting on itself.
        var port = new FakeSerialPort();
        using var wrapper = new SerialPortWrapper(port);
        wrapper.Open();

        var done = new ManualResetEventSlim(false);
        wrapper.BytesReceived += (s, _) =>
        {
            ((SerialPortWrapper)s!).Close();
            done.Set();
        };

        port.SimulateReceive(new byte[] { 0x01 });

        Assert.True(done.Wait(WaitMs), "The handler never returned from Close().");
        Assert.False(wrapper.IsOpen);
    }

    [Fact]
    public void Dispose_CalledFromInsideAHandler_DoesNotDeadlock()
    {
        var port = new FakeSerialPort();
        var wrapper = new SerialPortWrapper(port);
        wrapper.Open();

        var done = new ManualResetEventSlim(false);
        wrapper.BytesReceived += (s, _) =>
        {
            ((SerialPortWrapper)s!).Dispose();
            done.Set();
        };

        port.SimulateReceive(new byte[] { 0x01 });

        Assert.True(done.Wait(WaitMs), "The handler never returned from Dispose().");
    }

    [Fact]
    public void ThrowingHandler_DoesNotStopLaterDeliveries()
    {
        var port = new FakeSerialPort();
        using var wrapper = new SerialPortWrapper(port);
        wrapper.Open();

        int delivered = 0;
        var second = new ManualResetEventSlim(false);
        wrapper.BytesReceived += (_, _) =>
        {
            if (Interlocked.Increment(ref delivered) == 2) second.Set();
            throw new InvalidOperationException("handler blew up");
        };

        port.SimulateReceive(new byte[] { 0x01 });
        port.SimulateReceive(new byte[] { 0x02 });

        Assert.True(second.Wait(WaitMs), "The callback loop stopped after the first handler threw.");
        Assert.True(wrapper.IsOpen);
    }

    // ─── Teardown / reopen race ──────────────────────────────────────────────

    [Fact]
    public async Task Open_DoesNotPublishASessionWhileACloseIsParked()
    {
        // Close() clears _open, then parks in WaitForCallbackLease waiting for the
        // running handler. Monitor.Wait releases _sync there, and at that moment
        // the teardown is only half done: _open is already false but the
        // generation has not been bumped and the port is still open.
        //
        // Without the _closing marker, an Open() arriving in that window sees
        // _open == false, publishes a whole new session, and the parked Close then
        // wakes up, bumps the generation and shuts the port the new session is
        // using — leaving the wrapper closed while its owner believes it is open.
        //
        // This race needs no overflow; a plain Close/Open pair reaches it. It was
        // originally found through the overflow-recovery path, which has since
        // been removed, so it is provoked directly here.
        var port = new FakeSerialPort();
        using var wrapper = new SerialPortWrapper(port);
        wrapper.Open();

        var handlerEntered = new ManualResetEventSlim(false);
        var release = new ManualResetEventSlim(false);
        EventHandler<byte[]> blocking = (_, _) =>
        {
            handlerEntered.Set();
            release.Wait(WaitMs);
        };
        wrapper.BytesReceived += blocking;

        port.SimulateReceive(new byte[] { 0x01 });
        Assert.True(handlerEntered.Wait(WaitMs), "The handler never ran.");

        // Close parks on the lease held by that handler.
        var closing = Task.Run(() => wrapper.Close());
        await Task.Delay(100);

        // Open must wait this out rather than publishing over a half-torn session.
        var opening = Task.Run(() => wrapper.Open());
        await Task.Delay(100);

        wrapper.BytesReceived -= blocking;
        release.Set();

        await closing.WaitAsync(TimeSpan.FromMilliseconds(WaitMs));
        await opening.WaitAsync(TimeSpan.FromMilliseconds(WaitMs));

        Assert.True(wrapper.IsOpen,
            "The parked Close() tore down the session Open() had already published.");

        // And the reopened session must actually work.
        var got = new ManualResetEventSlim(false);
        wrapper.BytesReceived += (_, _) => got.Set();
        port.SimulateReceive(new byte[] { 0x7F });

        Assert.True(got.Wait(WaitMs), "The reopened session did not deliver chunks.");
    }
}
