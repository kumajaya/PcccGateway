// SPDX-License-Identifier: LGPL-3.0-or-later
//
// PcccGateway - Protocol Gateway for PCCC over DF1, CSPv4, and EIP
// Copyright (c) 2026 Ketut Kumajaya
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

namespace PcccGateway.Common;

/// <summary>
/// Ring buffer implementation for efficient byte stream processing.
/// Used internally by DF1 transports to avoid List.RemoveAt overhead.
/// </summary>
internal sealed class RingBuffer
{
    private readonly byte[] _buffer;
    private int _head; // read index
    private int _tail; // write index
    private int _count;
    private readonly int _capacity;

    /// <summary>Initializes a new ring buffer with the specified capacity.</summary>
    /// <param name="capacity">Maximum number of bytes the buffer can hold. Default is 4096.</param>
    public RingBuffer(int capacity = 4096)
    {
        if (capacity <= 0)
            throw new ArgumentOutOfRangeException(nameof(capacity));

        _capacity = capacity;
        _buffer = new byte[capacity];
        _head = 0;
        _tail = 0;
        _count = 0;
    }

    /// <summary>Number of bytes currently stored in the buffer.</summary>
    public int Count => _count;

    /// <summary>Maximum capacity of the buffer.</summary>
    public int Capacity => _capacity;

    /// <summary>
    /// Adds a range of bytes to the ring buffer. Throws <see cref="InvalidOperationException"/>
    /// if the buffer does not have enough free space.
    /// </summary>
    /// <param name="data">Source byte array.</param>
    /// <param name="offset">Starting index in <paramref name="data"/>.</param>
    /// <param name="length">Number of bytes to copy.</param>
    public void AddRange(byte[] data, int offset, int length)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (offset < 0)
            throw new ArgumentOutOfRangeException(nameof(offset));
        if (length < 0)
            throw new ArgumentOutOfRangeException(nameof(length));
        if (offset > data.Length - length)
            throw new ArgumentOutOfRangeException(nameof(offset), "offset and length do not denote a valid range in data.");        if (length == 0) return;
        if (length > _capacity - _count)
            throw new InvalidOperationException("RingBuffer overflow");
        int written = 0;
        while (written < length)
        {
            int spaceToEnd = _capacity - _tail;
            int chunk = Math.Min(length - written, spaceToEnd);
            Array.Copy(data, offset + written, _buffer, _tail, chunk);
            _tail = (_tail + chunk) % _capacity;
            written += chunk;
        }
        _count += length;
    }

    /// <summary>
    /// Copies up to <paramref name="count"/> bytes from the buffer into
    /// <paramref name="destination"/> without advancing the read pointer.
    /// </summary>
    /// <param name="destination">Destination array.</param>
    /// <param name="destOffset">Starting offset in <paramref name="destination"/>.</param>
    /// <param name="count">Maximum number of bytes to copy.</param>
    /// <returns>Actual number of bytes copied (may be less than <paramref name="count"/> if buffer has fewer bytes).</returns>
    public int Peek(byte[] destination, int destOffset, int count)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destOffset < 0)
            throw new ArgumentOutOfRangeException(nameof(destOffset));
        if (count < 0)
            throw new ArgumentOutOfRangeException(nameof(count));

        int bytesToCopy = Math.Min(count, _count);
        if (destOffset > destination.Length - bytesToCopy)
            throw new ArgumentException("Destination buffer is too small.", nameof(destination));

        int tempHead = _head;
        int copied = 0;
        while (copied < bytesToCopy)
        {
            int spaceToEnd = _capacity - tempHead;
            int chunk = Math.Min(bytesToCopy - copied, spaceToEnd);
            Array.Copy(_buffer, tempHead, destination, destOffset + copied, chunk);
            tempHead = (tempHead + chunk) % _capacity;
            copied += chunk;
        }
        return copied;
    }

    /// <summary>
    /// Advances the read pointer by <paramref name="count"/> bytes, effectively
    /// removing them from the buffer.
    /// </summary>
    /// <param name="count">Number of bytes to consume.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="count"/> is negative.</exception>
    /// <exception cref="InvalidOperationException">Thrown when <paramref name="count"/> exceeds <see cref="Count"/>.</exception>
    public void Advance(int count)
    {
        // A negative count is a caller mistake; a count beyond Count is a buffer
        // state violation. Distinct causes, distinct exception types.
        if (count < 0)
            throw new ArgumentOutOfRangeException(nameof(count), "Count cannot be negative.");
        if (count > _count)
            throw new InvalidOperationException("Advance beyond count");
        _head = (_head + count) % _capacity;
        _count -= count;
        if (_count == 0) { _head = 0; _tail = 0; }
    }

    /// <summary>Resets the buffer to empty state.</summary>
    public void Clear()
    {
        _head = 0;
        _tail = 0;
        _count = 0;
    }

    /// <summary>Indexer to read a byte at a logical offset without advancing the read pointer.</summary>
    /// <param name="index">Logical index from the current read position (0 = oldest byte).</param>
    /// <returns>The byte at the specified position.</returns>
    /// <exception cref="IndexOutOfRangeException">Thrown when <paramref name="index"/> is out of range.</exception>
    public byte this[int index]
    {
        get
        {
            if (index < 0 || index >= _count) throw new IndexOutOfRangeException();
            return _buffer[(_head + index) % _capacity];
        }
    }
}
