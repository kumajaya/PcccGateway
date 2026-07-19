using System.Diagnostics;
using System.IO.Ports;
using PcccGateway.Client;
using PcccGateway.Common;
using PcccGateway.Interface;
using Xunit;

namespace PcccGateway.Tests;

/// <summary>
/// Re-entrancy of the public transport callbacks. All three pass.
///
/// They were written RED against the previous design, where receive-path events
/// were raised inline on the SerialPortWrapper callback thread — the only thread
/// that could parse inbound bytes. A handler calling SendFrame() there starved
/// the parsing of its own ACK, and the send failed every time. Moving those
/// events to DF1BaseTransport's callback executor turned the first one green.
///
/// What each guards now:
///   HandlerCallingSendFrame_...      a handler may send and be answered
///   HandlerCallingClose_...          a handler may close; SerialPortWrapper's
///                                    callback-lease reentrancy guard holds
///   Close_DoesNotWaitForARunningHandler
///                                    teardown is not hostage to a subscriber
///
/// The second one never failed. It was written expecting a teardown deadlock
/// that turned out not to exist, and disproving that claim was worth as much as
/// confirming the first.
///
/// Every wait here is awaited rather than blocked on: a test that may be proving
/// a deadlock must never park the test thread on the thing that deadlocks.
/// </summary>
public class DF1CallbackReentrancyTests
{
    // ─── Helpers ────────────────────────────────────────────────────────────

    /// <summary>
    /// Awaits <paramref name="task"/> with a deadline, failing the test rather
    /// than hanging the run if it never completes.
    /// </summary>
    private static async Task AssertCompletesAsync(Task task, int timeoutMs, string because)
    {
        Task finished = await Task.WhenAny(task, Task.Delay(timeoutMs)).ConfigureAwait(false);
        Assert.True(ReferenceEquals(finished, task), because);
        await task.ConfigureAwait(false);   // surface any exception the task carries
    }

    /// <summary>
    /// A signal that can be awaited. Continuations are forced asynchronous so an
    /// awaiting test never resumes inline on the transport's callback thread.
    /// </summary>
    private static TaskCompletionSource NewSignal() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>
    /// Wraps a DF1 payload as DLE STX ... DLE ETX + CRC-16. The payloads used
    /// here deliberately contain no 0x10 byte, so no DLE stuffing is needed and
    /// the frame can be built without reaching into internal helpers.
    /// </summary>
    private static byte[] BuildDataFrame(byte[] payload)
    {
        Assert.DoesNotContain((byte)0x10, payload);

        ushort crc = DF1BaseTransport.CalculateChecksum(payload, CheckSumOptions.Crc);

        var frame = new byte[2 + payload.Length + 2 + 2];
        int i = 0;
        frame[i++] = 0x10;                  // DLE
        frame[i++] = 0x02;                  // STX
        Array.Copy(payload, 0, frame, i, payload.Length);
        i += payload.Length;
        frame[i++] = 0x10;                  // DLE
        frame[i++] = 0x03;                  // ETX
        frame[i++] = (byte)(crc & 0xFF);
        frame[i] = (byte)((crc >> 8) & 0xFF);
        return frame;
    }

    /// <summary>A valid inbound reply: DST=1, SRC=0, CMD=0x4F, STS=0, TNS=0xABCD.</summary>
    private static byte[] InboundReply() =>
        BuildDataFrame(new byte[] { 0x01, 0x00, 0x4F, 0x00, 0xCD, 0xAB });

    /// <summary>An outbound request the handler can try to send.</summary>
    private static byte[] OutboundRequest() =>
        new byte[] { 0x01, 0x00, 0x0F, 0x00, 0x01, 0x00 };

    /// <summary>
    /// Serial port stand-in: records everything written and lets the test push
    /// inbound bytes at a chosen moment. Bytes are delivered on the calling
    /// thread, exactly as the real driver's DataReceived event does.
    /// </summary>
    private sealed class ProgrammableSerialPort : ISerialPort
    {
        private readonly List<byte[]> _writes = new();

        public event EventHandler<byte[]>? BytesReceived;

        public bool IsOpen { get; private set; }
        public int BaudRate => 19200;
        public Parity Parity => Parity.None;
        public int BytesToRead => 0;
        public bool RtsEnable { get; set; }
        public bool DtrEnable { get; set; }

        public int WriteCount { get { lock (_writes) { return _writes.Count; } } }

        public void Open() => IsOpen = true;
        public void Close() => IsOpen = false;
        public void Dispose() => IsOpen = false;

        public void Write(byte[] buffer, int offset, int count)
        {
            var copy = new byte[count];
            Array.Copy(buffer, offset, copy, 0, count);
            lock (_writes) { _writes.Add(copy); }
        }

        public int Read(byte[] buffer, int offset, int count) => 0;

        public void Inject(byte[] data) => BytesReceived?.Invoke(this, data);

        /// <summary>Completes once at least <paramref name="count"/> writes have been recorded.</summary>
        public async Task<bool> WaitForWritesAsync(int count, int timeoutMs)
        {
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < timeoutMs)
            {
                if (WriteCount >= count) return true;
                await Task.Delay(5).ConfigureAwait(false);
            }
            return false;
        }
    }

    // ─── Tests ──────────────────────────────────────────────────────────────

    /// <summary>
    /// A RawFrameReceived handler sends a frame and the peer answers it promptly.
    /// The send must succeed.
    ///
    /// This is the one the callback executor fixed. Inline on the parsing thread,
    /// the handler occupied the only thread that could parse the ACK it waited
    /// for, so the wait ran out and SendFrame threw TimeoutException even though
    /// the ACK had arrived on time.
    /// </summary>
    [Fact]
    public async Task HandlerCallingSendFrame_SucceedsWhenPeerAcksPromptly()
    {
        var fake = new ProgrammableSerialPort();
        var wrapper = new SerialPortWrapper(fake);
        var transport = new DF1FullDuplexTransport(wrapper) { MaxTicks = 25 }; // 500 ms

        try
        {
            transport.Open();

            Exception? handlerError = null;
            var handlerDone = NewSignal();

            transport.RawFrameReceived += (_, _) =>
            {
                try { transport.SendFrame(OutboundRequest()); }
                catch (Exception ex) { handlerError = ex; }
                finally { handlerDone.TrySetResult(); }
            };

            // Answer the handler's frame with DLE ACK as soon as it reaches the
            // wire. Write 1 is the transport's own ACK for the inbound reply;
            // write 2 is the frame the handler sends.
            Task peer = Task.Run(async () =>
            {
                if (await fake.WaitForWritesAsync(2, 2000).ConfigureAwait(false))
                    fake.Inject(new byte[] { 0x10, 0x06 });   // DLE ACK
            });

            fake.Inject(InboundReply());

            await AssertCompletesAsync(handlerDone.Task, 5000, "the handler never returned");
            await AssertCompletesAsync(peer, 2000, "the peer task never finished");

            Assert.Null(handlerError);
        }
        finally
        {
            await AssertDisposesAsync(transport);
        }
    }

    /// <summary>
    /// Disposes on a worker thread and fails the test if that does not complete,
    /// or if it throws. Cleanup is exactly where the lifecycle regressions these
    /// tests exist for would surface, so a hung or throwing Dispose() must not be
    /// swallowed into a green run.
    /// </summary>
    private static async Task AssertDisposesAsync(IDisposable disposable) =>
        await AssertCompletesAsync(Task.Run(disposable.Dispose), 5000,
            "Dispose() did not complete").ConfigureAwait(false);

    /// <summary>
    /// A RawFrameReceived handler closes the transport. Close() must return.
    ///
    /// Written to expose a suspected permanent teardown cycle — Close() holding
    /// _txLock while base.Close() waited for the wrapper's callback lease, with
    /// the handler holding that lease waiting for _txLock. It passed first run:
    /// SerialPortWrapper.WaitForCallbackLease() returns immediately when the
    /// caller is its own callback thread, so the cycle never formed.
    ///
    /// Since the callback executor landed the handler no longer runs on the
    /// wrapper's callback thread at all, so that lease is not even contended.
    /// The test is kept because the property it asserts still matters: a
    /// subscriber may close the transport from inside a handler.
    /// </summary>
    [Fact]
    public async Task HandlerCallingClose_DoesNotDeadlock()
    {
        var fake = new ProgrammableSerialPort();
        var wrapper = new SerialPortWrapper(fake);
        var transport = new DF1FullDuplexTransport(wrapper);

        try
        {
            transport.Open();

            var closeReturned = NewSignal();

            transport.RawFrameReceived += (_, _) =>
            {
                try { transport.Close(); }
                finally { closeReturned.TrySetResult(); }
            };

            fake.Inject(InboundReply());

            await AssertCompletesAsync(closeReturned.Task, 5000,
                "Close() called from a RawFrameReceived handler did not return");
        }
        finally
        {
            // Close() alone leaves the wrapper's two lifetime tasks and the
            // transport's callback pump running: only Dispose() completes their
            // channels. Without this the test roots all three until the process
            // exits.
            await AssertDisposesAsync(transport);
        }
    }

    /// <summary>
    /// Close() does NOT wait for a running handler, and must not.
    ///
    /// An earlier version of this test claimed the opposite and asserted only
    /// that Close() finished within five seconds — which it would also do if it
    /// returned instantly. The claim was true before the callback executor
    /// landed, when handlers ran on the wrapper's callback thread and
    /// SerialPortWrapper.Close() waited for that lease. Handlers now run on the
    /// transport's own executor, which Close() never touches, so teardown is no
    /// longer hostage to a subscriber. That is the better property; this test now
    /// pins it down instead of describing the old one.
    ///
    /// Dispose() is the call that does drain the executor.
    /// </summary>
    [Fact]
    public async Task Close_DoesNotWaitForARunningHandler()
    {
        var fake = new ProgrammableSerialPort();
        var wrapper = new SerialPortWrapper(fake);
        var transport = new DF1FullDuplexTransport(wrapper);

        // ManualResetEventSlim rather than a Task: the handler has to block its
        // thread outright, which is the condition under test.
        using var releaseHandler = new ManualResetEventSlim(false);

        try
        {
            transport.Open();

            var handlerStarted = NewSignal();
            var handlerFinished = NewSignal();

            transport.RawFrameReceived += (_, _) =>
            {
                handlerStarted.TrySetResult();
                releaseHandler.Wait(5000);
                handlerFinished.TrySetResult();
            };

            fake.Inject(InboundReply());
            await AssertCompletesAsync(handlerStarted.Task, 2000, "the handler never ran");

            Task close = Task.Run(() => transport.Close());
            await AssertCompletesAsync(close, 5000, "Close() blocked on a running handler");

            Assert.False(handlerFinished.Task.IsCompleted,
                "Close() returned only after the handler finished — it is expected not to wait for it");

            releaseHandler.Set();
            await AssertCompletesAsync(handlerFinished.Task, 2000, "the handler never finished");
        }
        finally
        {
            releaseHandler.Set();   // never leave the executor thread parked
            await AssertDisposesAsync(transport);
        }
    }
}
