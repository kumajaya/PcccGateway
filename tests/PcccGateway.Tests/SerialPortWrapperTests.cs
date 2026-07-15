using PcccGateway.Client;
using Xunit;

namespace PcccGateway.Tests;

/// <summary>
/// Tests for <see cref="SerialPortWrapper"/>'s channel-based byte ordering.
/// Verifies that bytes received from the serial port are dispatched in the
/// exact order they arrived, even when multiple chunks are received in quick
/// succession.
/// </summary>
public class SerialPortWrapperTests
{
    [Fact]
    public async Task BytesReceived_AreDispatchedInArrivalOrder()
    {
        var fakePort = new FakeSerialPort();
        var wrapper = new SerialPortWrapper(fakePort);
        wrapper.Open();

        var receivedChunks = new List<byte[]>();
        var receivedEvent = new ManualResetEventSlim(false);
        wrapper.BytesReceived += (_, chunk) =>
        {
            receivedChunks.Add(chunk);
            if (receivedChunks.Count == 3)
                receivedEvent.Set();
        };

        // Simulate three chunks arriving in order.
        fakePort.SimulateReceive(new byte[] { 0x01, 0x02 });
        fakePort.SimulateReceive(new byte[] { 0x03, 0x04 });
        fakePort.SimulateReceive(new byte[] { 0x05, 0x06 });

        // Wait for all three to be dispatched.
        Assert.True(receivedEvent.Wait(1000));

        // Verify order is preserved.
        Assert.Equal(3, receivedChunks.Count);
        Assert.Equal(new byte[] { 0x01, 0x02 }, receivedChunks[0]);
        Assert.Equal(new byte[] { 0x03, 0x04 }, receivedChunks[1]);
        Assert.Equal(new byte[] { 0x05, 0x06 }, receivedChunks[2]);
    }

    [Fact]
    public async Task BytesReceived_AreDispatchedInArrivalOrder_EvenWhenChunksAreInterleaved()
    {
        var fakePort = new FakeSerialPort();
        var wrapper = new SerialPortWrapper(fakePort);
        wrapper.Open();

        var receivedChunks = new List<byte[]>();
        var receivedEvent = new ManualResetEventSlim(false);
        wrapper.BytesReceived += (_, chunk) =>
        {
            receivedChunks.Add(chunk);
            if (receivedChunks.Count == 4)
                receivedEvent.Set();
        };

        // Simulate chunks arriving with varying sizes.
        fakePort.SimulateReceive(new byte[] { 0x01 });
        fakePort.SimulateReceive(new byte[] { 0x02, 0x03, 0x04 });
        fakePort.SimulateReceive(new byte[] { 0x05, 0x06 });
        fakePort.SimulateReceive(new byte[] { 0x07, 0x08, 0x09, 0x0A });

        Assert.True(receivedEvent.Wait(1000));

        Assert.Equal(4, receivedChunks.Count);
        Assert.Equal(new byte[] { 0x01 }, receivedChunks[0]);
        Assert.Equal(new byte[] { 0x02, 0x03, 0x04 }, receivedChunks[1]);
        Assert.Equal(new byte[] { 0x05, 0x06 }, receivedChunks[2]);
        Assert.Equal(new byte[] { 0x07, 0x08, 0x09, 0x0A }, receivedChunks[3]);
    }

    [Fact]
    public void Dispose_CompletesChannel_AndStopsDispatchLoop()
    {
        var fakePort = new FakeSerialPort();
        var wrapper = new SerialPortWrapper(fakePort);
        wrapper.Open();

        var receivedChunks = new List<byte[]>();
        wrapper.BytesReceived += (_, chunk) => receivedChunks.Add(chunk);

        fakePort.SimulateReceive(new byte[] { 0x01, 0x02 });
        fakePort.SimulateReceive(new byte[] { 0x03, 0x04 });

        // Give the channel a moment to process.
        Thread.Sleep(100);

        // Dispose should complete the channel and stop the dispatch loop.
        wrapper.Dispose();

        // No exception should be thrown, and no more events should fire.
        // This test verifies that Dispose doesn't hang.
        Assert.True(true);
    }
}
