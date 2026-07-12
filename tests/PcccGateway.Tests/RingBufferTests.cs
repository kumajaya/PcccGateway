using PcccGateway.Common;
using Xunit;

namespace PcccGateway.Tests;

/// <summary>
/// Tests for the internal <see cref="RingBuffer"/> used by the DF1 receive path.
/// </summary>
public class RingBufferTests
{
    [Fact]
    public void AddRange_Then_PeekAndAdvance()
    {
        var rb = new RingBuffer(16);
        rb.AddRange(new byte[] { 1, 2, 3, 4 }, 0, 4);
        Assert.Equal(4, rb.Count);

        var dst = new byte[4];
        int n = rb.Peek(dst, 0, 4);
        Assert.Equal(4, n);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, dst);

        rb.Advance(2);
        Assert.Equal(2, rb.Count);
        Assert.Equal(3, rb[0]);   // indexer is relative to the read pointer
        Assert.Equal(4, rb[1]);
    }

    [Fact]
    public void WrapsAround_WhenWriteCrossesEnd()
    {
        var rb = new RingBuffer(8);
        rb.AddRange(new byte[] { 1, 2, 3, 4, 5, 6 }, 0, 6);
        rb.Advance(5);                                  // head near the end
        rb.AddRange(new byte[] { 7, 8, 9, 10 }, 0, 4);  // write wraps past capacity

        Assert.Equal(5, rb.Count);
        var dst = new byte[5];
        rb.Peek(dst, 0, 5);
        Assert.Equal(new byte[] { 6, 7, 8, 9, 10 }, dst);
    }

    [Fact]
    public void Overflow_Throws()
    {
        var rb = new RingBuffer(4);
        Assert.Throws<InvalidOperationException>(
            () => rb.AddRange(new byte[] { 1, 2, 3, 4, 5 }, 0, 5));
    }

    [Fact]
    public void Advance_BeyondCount_Throws()
    {
        var rb = new RingBuffer(4);
        rb.AddRange(new byte[] { 1, 2 }, 0, 2);
        Assert.Throws<InvalidOperationException>(() => rb.Advance(3));
    }

    [Fact]
    public void Clear_Resets()
    {
        var rb = new RingBuffer(4);
        rb.AddRange(new byte[] { 1, 2, 3 }, 0, 3);
        rb.Clear();
        Assert.Equal(0, rb.Count);
    }
}
