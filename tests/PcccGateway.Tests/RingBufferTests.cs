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

    // ─── Constructor guards ──────────────────────────────────────────

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Ctor_NonPositiveCapacity_Throws(int capacity)
    {
        // A zero capacity used to construct successfully and then fail later with
        // DivideByZeroException from the "% _capacity" in Advance and the indexer,
        // far from the actual mistake.
        Assert.Throws<ArgumentOutOfRangeException>(() => new RingBuffer(capacity));
    }

    // ─── Advance guards ──────────────────────────────────────────────

    [Fact]
    public void Advance_NegativeCount_Throws()
    {
        var rb = new RingBuffer(8);
        rb.AddRange(new byte[] { 1, 2, 3, 4 }, 0, 4);

        Assert.Throws<ArgumentOutOfRangeException>(() => rb.Advance(-1));
    }

    [Fact]
    public void Advance_NegativeCount_DoesNotCorruptState()
    {
        // Regression test for the silent-corruption bug.
        //
        // Before the guard, Advance(-1) slipped past the "count > _count" check and
        // executed _head = (_head + (-1)) % _capacity, driving _head negative while
        // _count -= (-1) INCREASED the reported count. The buffer then claimed to
        // hold more bytes than were ever written and the indexer read stale slots.
        // Nothing threw at the point of the mistake; the damage surfaced later in
        // DF1 framing, where it is far harder to trace.
        var rb = new RingBuffer(8);
        rb.AddRange(new byte[] { 1, 2, 3, 4 }, 0, 4);
        rb.Advance(2);                       // head = 2, count = 2

        Assert.Throws<ArgumentOutOfRangeException>(() => rb.Advance(-1));

        // State must be exactly as it was before the rejected call.
        Assert.Equal(2, rb.Count);
        Assert.Equal(3, rb[0]);
        Assert.Equal(4, rb[1]);

        // And the buffer must still be usable.
        rb.Advance(2);
        Assert.Equal(0, rb.Count);
    }

    [Fact]
    public void Advance_Zero_IsNoOp()
    {
        var rb = new RingBuffer(4);
        rb.AddRange(new byte[] { 1, 2 }, 0, 2);

        rb.Advance(0);

        Assert.Equal(2, rb.Count);
        Assert.Equal(1, rb[0]);
    }

    // ─── AddRange guards ─────────────────────────────────────────────

    [Fact]
    public void AddRange_NullData_Throws()
    {
        var rb = new RingBuffer(8);
        Assert.Throws<ArgumentNullException>(() => rb.AddRange(null!, 0, 1));
    }

    [Theory]
    [InlineData(-1, 1)]    // negative offset
    [InlineData(0, -1)]    // negative length
    [InlineData(2, 3)]     // offset + length runs past the end of data
    [InlineData(5, 1)]     // offset alone is past the end of data
    public void AddRange_OutOfRangeArguments_Throw(int offset, int length)
    {
        var rb = new RingBuffer(8);
        var data = new byte[4];

        Assert.Throws<ArgumentOutOfRangeException>(() => rb.AddRange(data, offset, length));
    }

    [Fact]
    public void AddRange_ZeroLengthAtEndOfData_IsAccepted()
    {
        // The range check is written as "offset > data.Length - length", which stays
        // correct for the boundary case offset == data.Length when length == 0.
        // (Writing it as "offset + length > data.Length" would be equivalent here but
        // can overflow for large values, so the current form is the right one.)
        var rb = new RingBuffer(8);
        var data = new byte[4];

        rb.AddRange(data, 4, 0);
        rb.AddRange(Array.Empty<byte>(), 0, 0);

        Assert.Equal(0, rb.Count);
    }

    [Fact]
    public void AddRange_RejectedCall_DoesNotChangeCount()
    {
        var rb = new RingBuffer(4);
        rb.AddRange(new byte[] { 1, 2 }, 0, 2);

        Assert.Throws<InvalidOperationException>(
            () => rb.AddRange(new byte[] { 3, 4, 5 }, 0, 3));   // would overflow

        Assert.Equal(2, rb.Count);
        Assert.Equal(1, rb[0]);
        Assert.Equal(2, rb[1]);
    }

    // ─── Peek guards ─────────────────────────────────────────────────

    [Fact]
    public void Peek_NullDestination_Throws()
    {
        var rb = new RingBuffer(8);
        rb.AddRange(new byte[] { 1, 2 }, 0, 2);

        Assert.Throws<ArgumentNullException>(() => rb.Peek(null!, 0, 2));
    }

    [Theory]
    [InlineData(-1, 1)]    // negative destOffset
    [InlineData(0, -1)]    // negative count
    public void Peek_OutOfRangeArguments_Throw(int destOffset, int count)
    {
        var rb = new RingBuffer(8);
        rb.AddRange(new byte[] { 1, 2 }, 0, 2);
        var dst = new byte[4];

        Assert.Throws<ArgumentOutOfRangeException>(() => rb.Peek(dst, destOffset, count));
    }

    [Fact]
    public void Peek_DestinationTooSmall_Throws()
    {
        // Previously this failed inside Array.Copy with the same exception type but a
        // message pointing at the internal copy rather than the caller's argument.
        var rb = new RingBuffer(8);
        rb.AddRange(new byte[] { 1, 2, 3, 4 }, 0, 4);
        var dst = new byte[2];

        Assert.Throws<ArgumentException>(() => rb.Peek(dst, 0, 4));
    }

    [Fact]
    public void Peek_ReturnsFewerBytes_WhenBufferHasFewerThanRequested()
    {
        var rb = new RingBuffer(8);
        rb.AddRange(new byte[] { 1, 2 }, 0, 2);
        var dst = new byte[4];

        int n = rb.Peek(dst, 0, 4);

        Assert.Equal(2, n);
        Assert.Equal(new byte[] { 1, 2, 0, 0 }, dst);
    }

    [Fact]
    public void Peek_DoesNotAdvanceReadPointer()
    {
        var rb = new RingBuffer(8);
        rb.AddRange(new byte[] { 1, 2, 3 }, 0, 3);
        var dst = new byte[3];

        rb.Peek(dst, 0, 3);
        rb.Peek(dst, 0, 3);

        Assert.Equal(3, rb.Count);
        Assert.Equal(new byte[] { 1, 2, 3 }, dst);
    }

    [Fact]
    public void Peek_AtDestOffset_WritesAtThatOffset()
    {
        var rb = new RingBuffer(8);
        rb.AddRange(new byte[] { 7, 8 }, 0, 2);
        var dst = new byte[4];

        int n = rb.Peek(dst, 2, 2);

        Assert.Equal(2, n);
        Assert.Equal(new byte[] { 0, 0, 7, 8 }, dst);
    }

    [Fact]
    public void Peek_ZeroBytesToCopy_WithDestOffsetPastEnd_Throws()
    {
        // Empty buffer, so bytesToCopy is 0 and nothing would be written. An earlier
        // revision returned 0 here without inspecting destOffset -- but only because
        // the copy loop never ran, so Array.Copy was never reached to complain. That
        // leniency was an accident of control flow, not a contract.
        //
        // The bounds check "destOffset > destination.Length - bytesToCopy" is the same
        // formula Array.Copy applies internally, and Array.Copy rejects these exact
        // arguments (verified on net8.0: ArgumentException, "Destination array was not
        // long enough"). Matching the platform is the intended behaviour.
        var rb = new RingBuffer(8);
        var dst = new byte[4];

        Assert.Throws<ArgumentException>(() => rb.Peek(dst, 5, 0));
    }

    [Fact]
    public void Peek_ZeroBytesToCopy_WithDestOffsetExactlyAtEnd_IsAccepted()
    {
        // The boundary one step lower must stay OPEN: destOffset == destination.Length
        // with nothing to copy is legal, because "destOffset > Length - 0" is false.
        // Array.Copy accepts the same case, so the two agree on both sides of the edge,
        // not merely on the fact that some inputs are rejected.
        var rb = new RingBuffer(8);
        var dst = new byte[4];

        int n = rb.Peek(dst, 4, 0);

        Assert.Equal(0, n);
    }

    [Fact]
    public void Peek_EmptyBuffer_DestOffsetInRange_ReturnsZero()
    {
        var rb = new RingBuffer(8);
        var dst = new byte[4];

        int n = rb.Peek(dst, 0, 4);

        Assert.Equal(0, n);
        Assert.Equal(new byte[] { 0, 0, 0, 0 }, dst);
    }

    // ─── Call pattern used by the DF1 receive path ───────────────────
    //
    // DF1FullDuplexTransport.OnBytesReceived and DF1HalfDuplexTransport.OnBytesReceived
    // are the only callers of Peek, and both call it identically:
    //
    //     if (_rxBuffer.Count < totalLen) break;                 // guard
    //     byte[] frame = ArrayPool<byte>.Shared.Rent(totalLen);
    //     _rxBuffer.Peek(frame, 0, totalLen);
    //
    // destOffset is always 0 and the guard keeps bytesToCopy > 0, so the zero-copy edge
    // above is unreachable in production. These tests pin the contract that IS exercised.

    [Fact]
    public void Peek_Df1CallPattern_ExactSizedDestination()
    {
        var rb = new RingBuffer(4096);
        var payload = new byte[] { 0x10, 0x02, 0x01, 0x00, 0x10, 0x03, 0xAB, 0xCD };
        rb.AddRange(payload, 0, payload.Length);

        var dst = new byte[payload.Length];
        int n = rb.Peek(dst, 0, payload.Length);

        Assert.Equal(payload.Length, n);
        Assert.Equal(payload, dst);
    }

    [Fact]
    public void Peek_Df1CallPattern_OversizedRentedDestination()
    {
        // ArrayPool.Rent(n) returns an array of AT LEAST n bytes, usually more. The
        // "destination too small" guard must tolerate that surplus, and Peek must not
        // write past `count`.
        var rb = new RingBuffer(4096);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        rb.AddRange(payload, 0, payload.Length);

        byte[] rented = System.Buffers.ArrayPool<byte>.Shared.Rent(payload.Length);
        try
        {
            Array.Clear(rented, 0, rented.Length);
            int n = rb.Peek(rented, 0, payload.Length);

            Assert.Equal(payload.Length, n);
            Assert.True(rented.Length >= payload.Length);
            for (int i = 0; i < payload.Length; i++)
                Assert.Equal(payload[i], rented[i]);
            for (int i = payload.Length; i < rented.Length; i++)
                Assert.Equal(0, rented[i]);
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(rented);
        }
    }

    [Fact]
    public void Peek_Df1CallPattern_AcrossWrap()
    {
        // The DF1 receive path routinely peeks a frame straddling the wrap point.
        //
        // The buffer must NOT be drained to empty first: Advance() resets _head and
        // _tail to zero once _count reaches zero, so the following write would start
        // at index 0 and never cross the wrap point. Retaining one byte keeps the
        // pointers where they are.
        var rb = new RingBuffer(8);
        rb.AddRange(new byte[] { 0, 0, 0, 0, 0, 0 }, 0, 6);
        rb.Advance(5);                                     // retain one byte at index 5
        rb.AddRange(new byte[] { 1, 2, 3, 4, 5 }, 0, 5);   // writes across the wrap point
        rb.Advance(1);                                     // drop the retained byte

        var dst = new byte[5];
        int n = rb.Peek(dst, 0, 5);

        Assert.Equal(5, n);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, dst);
    }

    // ─── Indexer guards ──────────────────────────────────────────────

    [Theory]
    [InlineData(-1)]
    [InlineData(2)]
    [InlineData(int.MaxValue)]
    public void Indexer_OutOfRange_Throws(int index)
    {
        var rb = new RingBuffer(8);
        rb.AddRange(new byte[] { 1, 2 }, 0, 2);

        Assert.Throws<IndexOutOfRangeException>(() => rb[index]);
    }

    [Fact]
    public void Indexer_ReadsRelativeToHead_AcrossWrap()
    {
        var rb = new RingBuffer(4);
        rb.AddRange(new byte[] { 1, 2, 3 }, 0, 3);
        rb.Advance(2);                            // head = 2, count = 1
        rb.AddRange(new byte[] { 4, 5 }, 0, 2);   // wraps past capacity

        Assert.Equal(3, rb.Count);
        Assert.Equal(3, rb[0]);
        Assert.Equal(4, rb[1]);
        Assert.Equal(5, rb[2]);
    }

    // ─── State invariants ────────────────────────────────────────────

    [Fact]
    public void DrainingCompletely_ResetsPointers_AllowingFullCapacityWrite()
    {
        // Advance() resets _head/_tail to 0 when the buffer empties, so a full-capacity
        // write must succeed afterwards even though the pointers had wrapped.
        var rb = new RingBuffer(4);
        rb.AddRange(new byte[] { 1, 2, 3 }, 0, 3);
        rb.Advance(3);
        Assert.Equal(0, rb.Count);

        rb.AddRange(new byte[] { 9, 8, 7, 6 }, 0, 4);

        Assert.Equal(4, rb.Count);
        var dst = new byte[4];
        rb.Peek(dst, 0, 4);
        Assert.Equal(new byte[] { 9, 8, 7, 6 }, dst);
    }

    [Fact]
    public void FillDrainCycles_WalkThePointersAroundTheBuffer()
    {
        // Same trap as the wrap test above: a cycle that drains to empty resets the
        // pointers to zero, so every iteration would start from the same place and
        // the wrap point would never be crossed however many times it ran. Keeping
        // one byte back each round walks _head and _tail around the buffer instead.
        var rb = new RingBuffer(8);
        var model = new Queue<byte>();
        byte next = 0;

        for (int cycle = 0; cycle < 20; cycle++)
        {
            var chunk = new byte[5];
            for (int i = 0; i < chunk.Length; i++)
            {
                chunk[i] = next++;
                model.Enqueue(chunk[i]);
            }
            rb.AddRange(chunk, 0, chunk.Length);

            Assert.Equal(model.Count, rb.Count);

            var dst = new byte[rb.Count];
            Assert.Equal(model.Count, rb.Peek(dst, 0, dst.Length));
            Assert.Equal(model.ToArray(), dst);

            // Consume all but one, so the buffer never empties.
            int consume = rb.Count - 1;
            rb.Advance(consume);
            for (int i = 0; i < consume; i++) model.Dequeue();

            Assert.Equal(1, rb.Count);
        }
    }
}
