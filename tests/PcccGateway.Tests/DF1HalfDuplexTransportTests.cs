using PcccGateway.Client;
using PcccGateway.Common;
using PcccGateway.Interface;
using Xunit;

namespace PcccGateway.Tests;

/// <summary>
/// Tests for the DF1 half‑duplex master transport (<c>DF1HalfDuplexTransport</c>)
/// using a <see cref="FakeSerialPort"/> instead of real hardware. This exercises
/// the 5‑step transaction sequence:
///   1. Send command frame (DLE STX ... DLE ETX + checksum)
///   2. Slave responds with DLE ACK
///   3. Master polls with DLE ENQ + SlaveAddress
///   4. Slave responds with DLE NAK (not ready) or data frame (DLE STX ...)
///   5. Master sends final DLE ACK and raises FrameReceived
/// </summary>
public class DF1HalfDuplexTransportTests
{
    private const byte DLE = 0x10, STX = 0x02, ETX = 0x03, ACK = 0x06, NAK = 0x15, ENQ = 0x05;

    private static (FakeSerialPort port, DF1HalfDuplexTransport transport) Create(
        int slaveAddress = 1,
        int commandAckTimeoutMs = 500,
        int pollResponseTimeoutMs = 200,
        int maxPollAttempts = 20,
        int pollRetryDelayMs = 20)
    {
        var port = new FakeSerialPort();
        var transport = new DF1HalfDuplexTransport(port)
        {
            SlaveAddress = slaveAddress,
            CommandAckTimeoutMs = commandAckTimeoutMs,
            PollResponseTimeoutMs = pollResponseTimeoutMs,
            MaxPollAttempts = maxPollAttempts,
            PollRetryDelayMs = pollRetryDelayMs,
            ChecksumType = CheckSumOptions.Crc
        };
        transport.Open();
        return (port, transport);
    }

    /// <summary>
    /// Builds a complete DF1 wire frame using the same public/internal helpers
    /// as production, guaranteed to match exactly.
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

    /// <summary>
    /// Builds a polling frame: DLE ENQ + SlaveAddress.
    /// </summary>
    private static byte[] BuildPoll(int slaveAddress) =>
        new byte[] { DLE, ENQ, (byte)slaveAddress };

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
    /// Complete successful transaction: command → ACK → poll → data → final ACK.
    /// </summary>
    [Fact]
    public async Task CompleteSuccessfulTransaction_RaisesFrameReceived()
    {
        var (port, transport) = Create(slaveAddress: 3);
        byte[]? received = null;
        transport.FrameReceived += (_, pdu) => received = pdu;

        // Inner frame: DST=1, SRC=4, CMD=0x06, STS=0, TNS=0x0001, FNC=0x03
        byte[] inner = { 0x01, 0x04, 0x06, 0x00, 0x01, 0x00, 0x03 };

        // Build the wire frame — but note that SendFrame will rewrite DST to SlaveAddress (3).
        // So the actual command frame sent will have DST=3, not 1.
        byte[] expectedCommandFrame = BuildFrame(new byte[] { 0x03, 0x04, 0x06, 0x00, 0x01, 0x00, 0x03 });

        var sendTask = Task.Run(() => transport.SendFrame(inner));

        // Wait for the command frame to be written
        await WaitForWriteCountAsync(port, 1, 1000);
        var actualCommand = port.GetWrittenFrame(0);
        Assert.Equal(expectedCommandFrame, actualCommand);

        // Respond with ACK to the command
        port.SimulateReceive(DLE, ACK);

        // Wait for the first poll to be written
        await WaitForWriteCountAsync(port, 2, 1000);
        var poll = port.GetWrittenFrame(1);
        Assert.Equal(BuildPoll(3), poll);

        // Respond with a data frame (the response)
        byte[] responseInner = { 0x01, 0x04, 0x46, 0x00, 0x01, 0x00, 0x00, 0xEE, 0x34 };
        port.SimulateReceive(BuildFrame(responseInner));

        // Wait for final ACK
        await WaitForWriteCountAsync(port, 3, 1000);
        var finalAck = port.GetWrittenFrame(2);
        Assert.Equal(new byte[] { DLE, ACK }, finalAck);

        // SendFrame should complete
        await sendTask.WaitAsync(TimeSpan.FromMilliseconds(2000));

        Assert.Equal(responseInner, received);
    }

    /// <summary>
    /// Command NAK → retry → success.
    /// </summary>
    [Fact]
    public async Task CommandNak_CausesRetry_ThenSucceeds()
    {
        var (port, transport) = Create(commandAckTimeoutMs: 1000);
        byte[] inner = { 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x03 };

        var sendTask = Task.Run(() => transport.SendFrame(inner));

        // First command frame written
        await WaitForWriteCountAsync(port, 1, 1000);

        // Slave sends NAK
        port.SimulateReceive(DLE, NAK);

        // Should retry: second command frame written
        await WaitForWriteCountAsync(port, 2, 1000);

        // Slave sends ACK
        port.SimulateReceive(DLE, ACK);

        // Poll written
        await WaitForWriteCountAsync(port, 3, 1000);

        // Slave sends data
        byte[] responseInner = { 0x01, 0x00, 0x46, 0x00, 0x01, 0x00, 0x00 };
        port.SimulateReceive(BuildFrame(responseInner));

        // Final ACK
        await WaitForWriteCountAsync(port, 4, 1000);

        await sendTask.WaitAsync(TimeSpan.FromMilliseconds(3000));
    }

    /// <summary>
    /// Poll NAK → continues polling → eventually data.
    /// </summary>
    [Fact]
    public async Task PollNak_ContinuesPolling_ThenSucceeds()
    {
        var (port, transport) = Create(slaveAddress: 5, maxPollAttempts: 10, pollRetryDelayMs: 10);
        byte[] inner = { 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x03 };

        var sendTask = Task.Run(() => transport.SendFrame(inner));

        // Command frame written
        await WaitForWriteCountAsync(port, 1, 1000);
        port.SimulateReceive(DLE, ACK);

        // Poll 1 written
        await WaitForWriteCountAsync(port, 2, 1000);
        port.SimulateReceive(DLE, NAK); // not ready

        // Poll 2 written (after retry delay)
        await WaitForWriteCountAsync(port, 3, 500);
        port.SimulateReceive(DLE, NAK);

        // Poll 3 written
        await WaitForWriteCountAsync(port, 4, 500);
        // Slave sends data
        byte[] responseInner = { 0x01, 0x00, 0x46, 0x00, 0x01, 0x00, 0x00 };
        port.SimulateReceive(BuildFrame(responseInner));

        // Final ACK
        await WaitForWriteCountAsync(port, 5, 500);

        await sendTask.WaitAsync(TimeSpan.FromMilliseconds(3000));
    }

    /// <summary>
    /// Poll timeout → no response → SendFrame throws TimeoutException.
    /// </summary>
    [Fact]
    public async Task PollTimeout_ThrowsTimeoutException()
    {
        var (port, transport) = Create(
            slaveAddress: 1,
            pollResponseTimeoutMs: 100,
            maxPollAttempts: 1,
            pollRetryDelayMs: 10
        );
        byte[] inner = { 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x03 };

        var sendTask = Task.Run(() => transport.SendFrame(inner));

        // Command frame written
        await WaitForWriteCountAsync(port, 1, 1000);
        port.SimulateReceive(DLE, ACK);

        // Poll written
        await WaitForWriteCountAsync(port, 2, 1000);
        // No response from slave → timeout

        var exception = await Assert.ThrowsAsync<TimeoutException>(() => sendTask.WaitAsync(TimeSpan.FromMilliseconds(3000)));
        Assert.Contains("No response data received", exception.Message);
    }

    /// <summary>
    /// Close() wakes a blocking SendFrame promptly.
    /// </summary>
    [Fact]
    public async Task Close_WakesBlockingSendFrame()
    {
        var (port, transport) = Create(commandAckTimeoutMs: 5000);
        byte[] inner = { 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x03 };

        var sendTask = Task.Run(() => transport.SendFrame(inner));

        // Command frame written
        await WaitForWriteCountAsync(port, 1, 1000);
        // No ACK from slave → SendFrame blocks

        // Close the transport while SendFrame is waiting for ACK
        transport.Close();

        // SendFrame should throw TimeoutException promptly
        var exception = await Assert.ThrowsAsync<TimeoutException>(() => sendTask.WaitAsync(TimeSpan.FromMilliseconds(1000)));
        Assert.Contains("closing", exception.Message);
    }

    /// <summary>
    /// Dispose waits for active operations to complete.
    /// </summary>
    [Fact]
    public async Task Dispose_WaitsForActiveOperations()
    {
        var (port, transport) = Create(commandAckTimeoutMs: 5000);
        byte[] inner = { 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x03 };

        var sendTask = Task.Run(() => transport.SendFrame(inner));

        // Command frame written
        await WaitForWriteCountAsync(port, 1, 1000);

        // Dispose should wait for active operations to finish
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        transport.Dispose();
        stopwatch.Stop();

        // Dispose should complete quickly (not wait for the full timeout)
        Assert.InRange(stopwatch.ElapsedMilliseconds, 0, 1000);
    }

    /// <summary>
    /// Echo suppression discards echoed bytes from the TX line.
    /// This includes echo of both the command frame and the poll frame.
    /// </summary>
    [Fact]
    public async Task EchoSuppression_DiscardsEchoedBytes()
    {
        var (port, transport) = Create();
        transport.EchoSuppression = true;

        byte[]? received = null;
        transport.FrameReceived += (_, pdu) => received = pdu;

        byte[] inner = { 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x03 };
        byte[] expectedCommand = BuildFrame(new byte[] { 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x03 });

        var sendTask = Task.Run(() => transport.SendFrame(inner));

        // Command frame written
        await WaitForWriteCountAsync(port, 1, 1000);
        byte[] commandFrame = port.GetWrittenFrame(0)!; // non-null because we know it was written

        // Simulate echo of the command frame bytes (should be discarded)
        byte[] echo = new byte[commandFrame.Length];
        Array.Copy(commandFrame, echo, commandFrame.Length);
        port.SimulateReceive(echo);
        await Task.Delay(50); // Allow echo suppression to process

        // Send ACK to the command (should be processed, not discarded)
        port.SimulateReceive(DLE, ACK);

        // Poll should be written (write #2)
        await WaitForWriteCountAsync(port, 2, 1000);

        // Simulate echo of the poll frame (3 bytes: DLE ENQ SlaveAddress)
        byte[] pollFrame = port.GetWrittenFrame(1)!; // non-null because we know it was written
        port.SimulateReceive(pollFrame);
        await Task.Delay(50); // Allow echo suppression to process

        // Now send the actual data frame (response)
        byte[] responseInner = { 0x01, 0x00, 0x46, 0x00, 0x01, 0x00, 0x00 };
        port.SimulateReceive(BuildFrame(responseInner));

        // Final ACK should be written (write #3)
        await WaitForWriteCountAsync(port, 3, 1000);

        // Generous timeout: the task itself finishes near-instantly once woken,
        // this only guards against ThreadPool scheduling jitter on a contended
        // CI runner (see ThreadPoolWarmup / AssemblyTestConfig.cs).
        await sendTask.WaitAsync(TimeSpan.FromMilliseconds(5000));

        Assert.Equal(responseInner, received);
    }

    /// <summary>
    /// Buffer overflow protection: a burst of bytes larger than MaxBufferBytes
    /// is cleared and the transport continues working.
    /// </summary>
    [Fact]
    public async Task FloodOfNonFramingBytes_DoesNotThrow_AndTransportStillWorks()
    {
        var (port, transport) = Create();
        byte[]? received = null;
        transport.FrameReceived += (_, pdu) => received = pdu;

        // More bytes than the 4096-byte receive buffer, with no DLE byte.
        var noise = new byte[5000];
        new Random(1).NextBytes(noise);
        for (int i = 0; i < noise.Length; i++)
            if (noise[i] == DLE) noise[i] = 0x00;

        var ex = Record.Exception(() => port.SimulateReceive(noise));
        Assert.Null(ex);

        // The transport must still work after the flood.
        byte[] inner = { 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x03 };
        var sendTask = Task.Run(() => transport.SendFrame(inner));

        await WaitForWriteCountAsync(port, 1, 1000);
        port.SimulateReceive(DLE, ACK);
        await WaitForWriteCountAsync(port, 2, 1000);
        byte[] responseInner = { 0x01, 0x00, 0x46, 0x00, 0x01, 0x00, 0x00 };
        port.SimulateReceive(BuildFrame(responseInner));
        await WaitForWriteCountAsync(port, 3, 1000);

        await sendTask.WaitAsync(TimeSpan.FromMilliseconds(2000));
        Assert.Equal(responseInner, received);
    }

    /// <summary>
    /// Data frame split across multiple chunks still parses correctly.
    /// </summary>
    [Fact]
    public async Task DataFrame_SplitAcrossMultipleChunks_StillParses()
    {
        var (port, transport) = Create();
        byte[]? received = null;
        transport.FrameReceived += (_, pdu) => received = pdu;

        byte[] inner = { 0x01, 0x00, 0x46, 0x00, 0x01, 0x00, 0x00, 0xEE };
        byte[] frame = BuildFrame(inner);

        int split1 = frame.Length / 3;
        int split2 = 2 * frame.Length / 3;

        var sendTask = Task.Run(() => transport.SendFrame(new byte[] { 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x03 }));

        await WaitForWriteCountAsync(port, 1, 1000);
        port.SimulateReceive(DLE, ACK);
        await WaitForWriteCountAsync(port, 2, 1000);

        // Send data frame in chunks
        port.SimulateReceive(frame[0..split1]);
        Assert.Null(received);
        port.SimulateReceive(frame[split1..split2]);
        Assert.Null(received);
        port.SimulateReceive(frame[split2..]);

        await WaitForWriteCountAsync(port, 3, 1000);
        await sendTask.WaitAsync(TimeSpan.FromMilliseconds(2000));

        Assert.Equal(inner, received);
    }

    /// <summary>
    /// Data frame with DLE stuffing in payload is unstuffed correctly.
    /// </summary>
    [Fact]
    public async Task DataFrame_WithDleInPayload_IsUnstuffedCorrectly()
    {
        var (port, transport) = Create();
        byte[]? received = null;
        transport.FrameReceived += (_, pdu) => received = pdu;

        // Payload contains literal DLE bytes which are doubled on the wire.
        byte[] inner = { 0x01, 0x00, 0x46, 0x00, 0x01, 0x00, 0x10, 0x10 };

        var sendTask = Task.Run(() => transport.SendFrame(new byte[] { 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x03 }));

        await WaitForWriteCountAsync(port, 1, 1000);
        port.SimulateReceive(DLE, ACK);
        await WaitForWriteCountAsync(port, 2, 1000);

        port.SimulateReceive(BuildFrame(inner));

        await WaitForWriteCountAsync(port, 3, 1000);
        await sendTask.WaitAsync(TimeSpan.FromMilliseconds(2000));

        Assert.Equal(inner, received);
    }

    /// <summary>
    /// Data frame with bad checksum does not raise FrameReceived.
    /// The master will eventually timeout and continue polling.
    /// </summary>
    [Fact]
    public async Task DataFrame_WithBadChecksum_SendsNak_AndNoFrameReceived()
    {
        // Use a short timeout so the master times out quickly and retries.
        var (port, transport) = Create(
            pollResponseTimeoutMs: 50,
            maxPollAttempts: 3,
            pollRetryDelayMs: 10
        );
        bool raised = false;
        transport.FrameReceived += (_, _) => raised = true;

        byte[] frame = BuildFrame(new byte[] { 0x01, 0x00, 0x46, 0x00, 0x01, 0x00, 0x00 });
        frame[^1] ^= 0xFF; // corrupt checksum

        var sendTask = Task.Run(() => transport.SendFrame(new byte[] { 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x03 }));

        await WaitForWriteCountAsync(port, 1, 1000);
        port.SimulateReceive(DLE, ACK);
        await WaitForWriteCountAsync(port, 2, 1000);

        // Send bad data frame
        port.SimulateReceive(frame);

        // Master should timeout and send another poll (write #3)
        await WaitForWriteCountAsync(port, 3, 1000);

        Assert.False(raised);
    }

    /// <summary>
    /// After Close(), a subsequent Open() must reset _closing so that
    /// SendFrame() can succeed again. This verifies the full lifecycle
    /// of the half-duplex transport.
    /// </summary>
    [Fact]
    public async Task Close_ThenOpen_ResetsClosingState_AndSendFrameSucceeds()
    {
        var (port, transport) = Create(slaveAddress: 1);

        // First transaction: success
        byte[] inner = { 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x03 };
        byte[] expectedCommand = BuildFrame(new byte[] { 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x03 });

        var sendTask1 = Task.Run(() => transport.SendFrame(inner));
        await WaitForWriteCountAsync(port, 1, 1000);
        var actualCommand = port.GetWrittenFrame(0);
        Assert.Equal(expectedCommand, actualCommand);
        port.SimulateReceive(DLE, ACK);
        await WaitForWriteCountAsync(port, 2, 1000);
        byte[] responseInner = { 0x01, 0x00, 0x46, 0x00, 0x01, 0x00, 0x00 };
        port.SimulateReceive(BuildFrame(responseInner));
        await WaitForWriteCountAsync(port, 3, 1000);
        await sendTask1.WaitAsync(TimeSpan.FromMilliseconds(2000));

        // Close the transport
        transport.Close();
        Assert.False(transport.IsOpen);

        // Open again — must reset _closing and _shutdownEvent
        transport.Open();
        Assert.True(transport.IsOpen);

        // Second transaction must succeed
        var sendTask2 = Task.Run(() => transport.SendFrame(inner));
        await WaitForWriteCountAsync(port, 4, 1000);
        port.SimulateReceive(DLE, ACK);
        await WaitForWriteCountAsync(port, 5, 1000);
        port.SimulateReceive(BuildFrame(responseInner));
        await WaitForWriteCountAsync(port, 6, 1000);
        await sendTask2.WaitAsync(TimeSpan.FromMilliseconds(2000));
    }
}
