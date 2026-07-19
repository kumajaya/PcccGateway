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

    private static bool SpinUntil(Func<bool> condition, int timeoutMs = WaitMs)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            if (condition()) return true;
            Thread.Sleep(10);
        }
        return condition();
    }

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

    // ─── Receive queue overflow ──────────────────────────────────────────────

    [Fact]
    public void ReceiveQueueOverflow_ClosesThePort()
    {
        // Both channels are bounded at 100. Blocking the one consumer lets the
        // pipeline fill (≈202 chunks buffered), after which TryWrite fails and
        // overflow recovery closes the session so the link supervisor reconnects
        // into a clean one rather than the wrapper silently dropping bytes.
        var port = new FakeSerialPort();
        using var wrapper = new SerialPortWrapper(port);
        wrapper.Open();

        var release = new ManualResetEventSlim(false);
        var handlerEntered = new ManualResetEventSlim(false);
        wrapper.BytesReceived += (_, _) =>
        {
            handlerEntered.Set();
            release.Wait(WaitMs);
        };

        port.SimulateReceive(new byte[] { 0x00 });
        Assert.True(handlerEntered.Wait(WaitMs), "The first chunk was never delivered.");

        for (int i = 0; i < 400; i++)
            port.SimulateReceive(new byte[] { (byte)i });

        // Recovery parks in WaitForCallbackLease until the blocked handler returns.
        release.Set();

        Assert.True(SpinUntil(() => !wrapper.IsOpen),
            "The port was not closed after the receive queue overflowed.");
    }

    [Fact]
    public void ReopenAfterOverflow_AcceptsChunksAgain()
    {
        // Open() resets _recoveryGeneration, so a session that follows an overflow
        // is not left permanently marked as already-recovered.
        var port = new FakeSerialPort();
        using var wrapper = new SerialPortWrapper(port);
        wrapper.Open();

        var release = new ManualResetEventSlim(false);
        var entered = new ManualResetEventSlim(false);
        EventHandler<byte[]> blocking = (_, _) => { entered.Set(); release.Wait(WaitMs); };
        wrapper.BytesReceived += blocking;

        port.SimulateReceive(new byte[] { 0x00 });
        Assert.True(entered.Wait(WaitMs));
        for (int i = 0; i < 400; i++)
            port.SimulateReceive(new byte[] { (byte)i });
        release.Set();

        Assert.True(SpinUntil(() => !wrapper.IsOpen), "Overflow did not close the port.");
        wrapper.BytesReceived -= blocking;

        // A fresh session must work normally.
        port.Open();                     // the fake's own flag, cleared by the close
        wrapper.Open();
        Assert.True(wrapper.IsOpen);

        var got = new ManualResetEventSlim(false);
        wrapper.BytesReceived += (_, _) => got.Set();
        port.SimulateReceive(new byte[] { 0x7F });

        Assert.True(got.Wait(WaitMs), "The reopened session did not deliver chunks.");
    }

    [Fact]
    public void OverflowRecovery_DoesNotCloseASessionThatWasAlreadyReplaced()
    {
        // Recovery runs on a queued task, so the session it refers to may already
        // have been closed and reopened by the time it executes. CloseInternal's
        // generation check is what stops it tearing down the newer one.
        var port = new FakeSerialPort();
        using var wrapper = new SerialPortWrapper(port);
        wrapper.Open();

        var release = new ManualResetEventSlim(false);
        var entered = new ManualResetEventSlim(false);
        EventHandler<byte[]> blocking = (_, _) => { entered.Set(); release.Wait(WaitMs); };
        wrapper.BytesReceived += blocking;

        port.SimulateReceive(new byte[] { 0x00 });
        Assert.True(entered.Wait(WaitMs));
        for (int i = 0; i < 400; i++)
            port.SimulateReceive(new byte[] { (byte)i });

        // Replace the session while recovery is still queued or parked.
        wrapper.BytesReceived -= blocking;
        release.Set();
        wrapper.Close();
        port.Open();
        wrapper.Open();

        // Give any stale recovery task time to run and do damage.
        Thread.Sleep(300);

        Assert.True(wrapper.IsOpen,
            "A stale overflow recovery closed a session that had already been replaced.");
    }
}
