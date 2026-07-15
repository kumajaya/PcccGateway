using PcccGateway.Client;
using PcccGateway.Common;
using Xunit;

namespace PcccGateway.Tests;

/// <summary>
/// Tests for the DF1 full-duplex receive state machine (<c>OnBytesReceived</c>)
/// and the <c>SendFrame</c>/ACK-NAK/ENQ signalling it drives, exercised through
/// a <see cref="FakeSerialPort"/> instead of real hardware. This is the most
/// complex, highest-risk logic in the transport layer — DLE/STX/ETX framing,
/// checksum validation, retry/backoff, and link-control handling — and
/// previously had no test coverage at all.
/// </summary>
public class DF1FullDuplexTransportTests
{
    private const byte DLE = 0x10, STX = 0x02, ETX = 0x03, ACK = 0x06, NAK = 0x15, ENQ = 0x05;

    private static (FakeSerialPort port, DF1FullDuplexTransport transport) Create()
    {
        var port = new FakeSerialPort();
        var transport = new DF1FullDuplexTransport(port);
        transport.Open();
        return (port, transport);
    }

    /// <summary>
    /// Helper: wait for the port's write count to reach the expected value.
    /// </summary>
    private static async Task WaitForWriteCountAsync(FakeSerialPort port, int expectedCount, int timeoutMs)
    {
        var start = DateTime.UtcNow;
        while (port.WrittenFrames.Count < expectedCount)
        {
            if ((DateTime.UtcNow - start).TotalMilliseconds > timeoutMs)
                throw new TimeoutException($"Expected write count {expectedCount}, but got {port.WrittenFrames.Count} after {timeoutMs}ms");
            await Task.Delay(10);
        }
    }

    /// <summary>
    /// Builds a complete DF1 wire frame using the same public/internal helpers
    /// <c>BuildWireFrame</c> is built from (DLE-stuffing + checksum), so the
    /// test frame is guaranteed to match production framing exactly without
    /// needing access to the protected <c>BuildWireFrame</c> method itself.
    /// </summary>
    private static byte[] BuildFrame(byte[] inner, CheckSumOptions cs = CheckSumOptions.Crc)
    {
        byte[] stuffed = DF1BaseTransport.ApplyDleStuffing(inner);
        ushort checksum = DF1BaseTransport.CalculateChecksum(inner, cs);
        int csLen = cs == CheckSumOptions.Crc ? 2 : 1;

        var frame = new byte[2 + stuffed.Length + 2 + csLen];
        int i = 0;
        frame[i++] = DLE; frame[i++] = STX;
        Array.Copy(stuffed, 0, frame, i, stuffed.Length); i += stuffed.Length;
        frame[i++] = DLE; frame[i++] = ETX;
        frame[i++] = (byte)(checksum & 0xFF);
        if (csLen == 2) frame[i] = (byte)((checksum >> 8) & 0xFF);
        return frame;
    }

    [Fact]
    public async Task ValidDataFrame_RaisesFrameReceived_AndAutoAcksIt()
    {
        var (port, transport) = Create();
        byte[]? received = null;
        transport.FrameReceived += (_, pdu) => received = pdu;

        byte[] inner = { 0x4F, 0x00, 0x01, 0x00, 0xAA, 0xBB };
        port.SimulateReceive(BuildFrame(inner));

        await Task.Delay(50); // give event time to fire
        Assert.Equal(inner, received);
        Assert.Contains(port.WrittenFrames, f => f.Length == 2 && f[0] == DLE && f[1] == ACK);
    }

    [Fact]
    public async Task DataFrame_WithDleInPayload_IsUnstuffedCorrectly()
    {
        var (port, transport) = Create();
        byte[]? received = null;
        transport.FrameReceived += (_, pdu) => received = pdu;

        // Payload itself contains literal 0x10 bytes, which BuildFrame doubles on
        // the wire; the receive state machine must skip the stuffed pairs while
        // scanning for the real terminating DLE ETX, then collapse them back.
        byte[] inner = { 0x01, 0x10, 0x02, 0x10, 0x03 };
        port.SimulateReceive(BuildFrame(inner));

        await Task.Delay(50);
        Assert.Equal(inner, received);
    }

    [Fact]
    public async Task DataFrame_SplitAcrossMultipleChunks_StillParsesCorrectly()
    {
        var (port, transport) = Create();
        byte[]? received = null;
        transport.FrameReceived += (_, pdu) => received = pdu;

        byte[] inner = { 0x11, 0x22, 0x33, 0x44 };
        byte[] frame = BuildFrame(inner);

        int split1 = frame.Length / 3;
        int split2 = 2 * frame.Length / 3;
        port.SimulateReceive(frame[0..split1]);
        Assert.Null(received);   // must not fire on a partial frame
        port.SimulateReceive(frame[split1..split2]);
        Assert.Null(received);
        port.SimulateReceive(frame[split2..]);

        await Task.Delay(50);
        Assert.Equal(inner, received);
    }

    [Fact]
    public async Task DataFrame_WithBadChecksum_SendsNak_AndDoesNotRaiseFrameReceived()
    {
        var (port, transport) = Create();
        bool raised = false;
        transport.FrameReceived += (_, _) => raised = true;

        byte[] frame = BuildFrame(new byte[] { 0x01, 0x02, 0x03 });
        frame[^1] ^= 0xFF; // corrupt the last checksum byte

        port.SimulateReceive(frame);

        await Task.Delay(50);
        Assert.False(raised);
        Assert.Contains(port.WrittenFrames, f => f.Length == 2 && f[0] == DLE && f[1] == NAK);
    }

    [Fact]
    public async Task GarbageBeforeFrame_IsDiscardedByteByByte_ThenFrameParsesNormally()
    {
        var (port, transport) = Create();
        byte[]? received = null;
        transport.FrameReceived += (_, pdu) => received = pdu;

        byte[] inner = { 0xAB, 0xCD };
        byte[] garbage = { 0x55, 0x99, 0x00, 0x7E }; // no DLE byte among these
        port.SimulateReceive(garbage.Concat(BuildFrame(inner)).ToArray());

        await Task.Delay(50);
        Assert.Equal(inner, received);
    }

    [Fact]
    public async Task AckByte_WakesPendingSendFrame_WithoutThrowing()
    {
        var (port, transport) = Create();

        var sendTask = Task.Run(() => transport.SendFrame(new byte[] { 0x01, 0x02 }));
        await WaitForWriteCountAsync(port, 1, 1000);

        port.SimulateReceive(DLE, ACK);

        await sendTask.WaitAsync(TimeSpan.FromMilliseconds(2000));
    }

    [Fact]
    public async Task NakByte_CausesRetry_ThenSucceedsOnAck()
    {
        var (port, transport) = Create();

        var sendTask = Task.Run(() => transport.SendFrame(new byte[] { 0x09 }));
        await WaitForWriteCountAsync(port, 1, 1000);

        port.SimulateReceive(DLE, NAK);
        await WaitForWriteCountAsync(port, 2, 1000);

        port.SimulateReceive(DLE, ACK);
        await sendTask.WaitAsync(TimeSpan.FromMilliseconds(2000));
    }

    [Fact]
    public async Task EnqAfterValidFrame_IsAcked()
    {
        var (port, transport) = Create();
        port.SimulateReceive(BuildFrame(new byte[] { 0x01 }));
        await Task.Delay(50);
        port.WrittenFrames.Clear(); // drop the ACK the data frame itself triggered

        port.SimulateReceive(DLE, ENQ);
        await Task.Delay(50);

        Assert.Contains(port.WrittenFrames, f => f.Length == 2 && f[0] == DLE && f[1] == ACK);
    }

    [Fact]
    public async Task EnqAfterInvalidFrame_IsNaked()
    {
        var (port, transport) = Create();
        byte[] frame = BuildFrame(new byte[] { 0x01 });
        frame[^1] ^= 0xFF; // corrupt checksum
        port.SimulateReceive(frame);
        await Task.Delay(50);
        port.WrittenFrames.Clear(); // drop the NAK the bad data frame itself triggered

        port.SimulateReceive(DLE, ENQ);
        await Task.Delay(50);

        Assert.Contains(port.WrittenFrames, f => f.Length == 2 && f[0] == DLE && f[1] == NAK);
    }

    /// <summary>
    /// Regression guard for the receive buffer's advertised overflow-safety path
    /// ("MaxBufferBytes: Safety limit" in DF1FullDuplexTransport). A burst of
    /// bytes larger than the receive buffer, with no recognisable frame in it,
    /// must be handled by clearing the buffer — not by an unhandled exception.
    /// </summary>
    [Fact]
    public async Task FloodOfNonFramingBytes_DoesNotThrow_AndTransportStillWorksAfterwards()
    {
        var (port, transport) = Create();
        byte[]? received = null;
        transport.FrameReceived += (_, pdu) => received = pdu;

        // More bytes than the 4096-byte receive buffer, with no DLE byte in it,
        // so nothing is ever recognised as a frame start.
        var noise = new byte[5000];
        new Random(1).NextBytes(noise);
        for (int i = 0; i < noise.Length; i++)
            if (noise[i] == DLE) noise[i] = 0x00;

        var ex = Record.Exception(() => port.SimulateReceive(noise));
        Assert.Null(ex);

        // The transport must still be able to parse a normal frame afterwards.
        byte[] inner = { 0x01, 0x02 };
        port.SimulateReceive(BuildFrame(inner));

        await Task.Delay(50);
        Assert.Equal(inner, received);
    }

    /// <summary>
    /// Close() wakes a blocking SendFrame promptly.
    /// </summary>
    [Fact]
    public async Task Close_WakesBlockingSendFrame()
    {
        var (port, transport) = Create();
        var sendTask = Task.Run(() => transport.SendFrame(new byte[] { 0x01, 0x02 }));

        await WaitForWriteCountAsync(port, 1, 1000);
        transport.Close();

        var ex = await Assert.ThrowsAsync<TimeoutException>(() => sendTask.WaitAsync(TimeSpan.FromMilliseconds(500)));
        Assert.Contains("closing", ex.Message);
    }

    /// <summary>
    /// SendEnqAndWaitForAck returns 0 on ACK.
    /// </summary>
    [Fact]
    public async Task SendEnqAndWaitForAck_ReturnsZeroOnAck()
    {
        var (port, transport) = Create();
        var task = Task.Run(() => transport.SendEnqAndWaitForAck());

        await WaitForWriteCountAsync(port, 1, 1000);
        var enqFrame = port.GetWrittenFrame(0);
        Assert.Equal(new byte[] { DLE, ENQ }, enqFrame);

        port.SimulateReceive(DLE, ACK);
        int result = await task;
        Assert.Equal(0, result);
    }

    /// <summary>
    /// SendEnqAndWaitForAck returns -2 on NAK.
    /// </summary>
    [Fact]
    public async Task SendEnqAndWaitForAck_ReturnsMinusTwoOnNak()
    {
        var (port, transport) = Create();
        var task = Task.Run(() => transport.SendEnqAndWaitForAck());

        await WaitForWriteCountAsync(port, 1, 1000);
        port.SimulateReceive(DLE, NAK);
        int result = await task;
        Assert.Equal(-2, result);
    }

    /// <summary>
    /// SendEnqAndWaitForAck returns -3 on timeout.
    /// </summary>
    [Fact]
    public async Task SendEnqAndWaitForAck_ReturnsMinusThreeOnTimeout()
    {
        var (port, transport) = Create();
        transport.MaxTicks = 10; // 10 * 20 = 200ms timeout

        var task = Task.Run(() => transport.SendEnqAndWaitForAck());

        await WaitForWriteCountAsync(port, 1, 1000);
        // No response → timeout
        int result = await task;
        Assert.Equal(-3, result);
    }

    /// <summary>
    /// After Close(), a subsequent Open() must reset _closing so that
    /// SendFrame() can succeed again. This regression test verifies the
    /// full lifecycle: Open → Close → Open → SendFrame succeeds.
    /// </summary>
    [Fact]
    public async Task Close_ThenOpen_ResetsClosingState_AndSendFrameSucceeds()
    {
        var (port, transport) = Create();

        // First transaction: success
        var sendTask1 = Task.Run(() => transport.SendFrame(new byte[] { 0x01, 0x02 }));
        await WaitForWriteCountAsync(port, 1, 1000);
        port.SimulateReceive(DLE, ACK);
        await sendTask1.WaitAsync(TimeSpan.FromMilliseconds(2000));

        // Close the transport
        transport.Close();
        Assert.False(transport.IsOpen);

        // Open again — this must reset _closing
        transport.Open();
        Assert.True(transport.IsOpen);

        // Second transaction must succeed (not throw "Send aborted: transport is closing")
        var sendTask2 = Task.Run(() => transport.SendFrame(new byte[] { 0x03, 0x04 }));
        await WaitForWriteCountAsync(port, 2, 1000);
        port.SimulateReceive(DLE, ACK);
        await sendTask2.WaitAsync(TimeSpan.FromMilliseconds(2000));
    }

    /// <summary>
    /// A frame that starts (DLE STX) but never receives its terminating DLE ETX
    /// within FrameTimeoutMs (500ms) must be discarded so the transport can
    /// resynchronise on the next real frame, instead of holding the stale bytes
    /// forever waiting for a completion that will never come. This requires an
    /// actual real-time wait (no injectable clock in production code), so the
    /// test is inherently a bit slow (~700ms) — that's the trade-off for testing
    /// genuine wall-clock timeout behaviour rather than mocking it away.
    /// </summary>
    [Fact]
    public async Task PartialFrame_ExceedingFrameTimeout_IsDiscarded_AndNextFrameParsesCorrectly()
    {
        var (port, transport) = Create();
        byte[]? received = null;
        transport.FrameReceived += (_, pdu) => received = pdu;

        // DLE STX followed by a couple of plain bytes — no DLE ETX ever arrives.
        port.SimulateReceive(DLE, STX, 0xAA, 0xBB);
        await Task.Delay(50);
        Assert.Null(received); // still waiting for more bytes, as expected

        // Let FrameTimeoutMs (500ms) elapse with nothing further arriving.
        await Task.Delay(700);

        // A fresh, complete, valid frame now arrives. The state machine must
        // notice the stale partial frame is too old, discard it, resynchronise
        // past the two leftover payload bytes (0xAA, 0xBB), and then parse this
        // new frame correctly — not get stuck waiting on the abandoned one.
        byte[] inner = { 0x77, 0x88 };
        port.SimulateReceive(BuildFrame(inner));

        await Task.Delay(50);
        Assert.Equal(inner, received);
    }
}
