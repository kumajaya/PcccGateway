using PcccGateway.Client;
using Xunit;

namespace PcccGateway.Tests;

/// <summary>
/// Tests for DF1 DLE byte-stuffing (every 0x10 in the payload is doubled on the
/// wire and collapsed back on receive).
/// </summary>
public class DleStuffingTests
{
    [Fact]
    public void ApplyStuffing_DoublesEachDle()
    {
        byte[] input    = { 0x01, 0x10, 0x02 };
        byte[] expected = { 0x01, 0x10, 0x10, 0x02 };
        Assert.Equal(expected, DF1BaseTransport.ApplyDleStuffing(input));
    }

    [Fact]
    public void ApplyStuffing_NoDle_IsUnchanged()
    {
        byte[] input = { 0x01, 0x02, 0x03 };
        Assert.Equal(input, DF1BaseTransport.ApplyDleStuffing(input));
    }

    [Theory]
    [InlineData(new byte[] { 0x10 })]
    [InlineData(new byte[] { 0x10, 0x10 })]
    [InlineData(new byte[] { 0x00, 0x10, 0x03, 0x10, 0x10, 0xFF })]
    [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04 })]
    public void StuffThenUnstuff_RoundTrips(byte[] payload)
    {
        byte[] stuffed = DF1BaseTransport.ApplyDleStuffing(payload);
        byte[] back     = DF1BaseTransport.RemoveDleStuffing(stuffed);
        Assert.Equal(payload, back);
    }
}
