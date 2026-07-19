using System.IO.Ports;
using System.Collections.Concurrent;
using PcccGateway.Interface;

namespace PcccGateway.Tests;

/// <summary>
/// In-memory <see cref="ISerialPort"/> test double used to drive DF1 transport
/// tests without a real (or virtual) COM port. Records every frame written to
/// the "wire" and lets a test inject bytes as if they arrived from the remote
/// peer, synchronously and in the order the test calls <see cref="SimulateReceive"/> —
/// mirroring how the real wrapper's dispatch loop invokes <c>BytesReceived</c>
/// for each chunk strictly in arrival order.
/// </summary>
internal sealed class FakeSerialPort : ISerialPort
{
    private bool _isOpen;

    public event EventHandler<byte[]>? BytesReceived;

    public bool IsOpen => _isOpen;
    public bool RtsEnable { get; set; }
    public bool DtrEnable { get; set; }
    public int BaudRate { get; set; } = 19200;
    public Parity Parity { get; set; } = Parity.None;

    /// <summary>
    /// Every frame handed to <see cref="Write"/>, in write order.
    /// Using <see cref="ConcurrentQueue{T}"/> ensures that reading
    /// <see cref="Count"/> in <c>WaitForWriteCountAsync</c> is safe
    /// without locking, eliminating a race condition present in the
    /// previous <see cref="List{T}"/> implementation.
    /// </summary>
    public ConcurrentQueue<byte[]> WrittenFrames { get; } = new();

    public void Open() => _isOpen = true;

    public void Close() => _isOpen = false;

    public void Write(byte[] buffer, int offset, int count)
    {
        var copy = new byte[count];
        Array.Copy(buffer, offset, copy, 0, count);
        WrittenFrames.Enqueue(copy);
    }

    /// <summary>
    /// Simulates bytes arriving from the remote peer in a single chunk.
    /// </summary>
    /// <remarks>
    /// This used to also enqueue the bytes into a private buffer so a later
    /// Read() could return them. Nothing ever called Read — the gateway's
    /// receive path is entirely event-driven — so that buffer, its lock, and
    /// the enqueue loop went with Read when it left ISerialPort. The fake now
    /// keeps one representation of what arrived instead of two, only one of
    /// which was ever observed.
    /// </remarks>
    public void SimulateReceive(params byte[] data)
    {
        BytesReceived?.Invoke(this, data);
    }

    /// <summary>Returns the frame at the specified index, or null if out of range.</summary>
    public byte[]? GetWrittenFrame(int index)
    {
        var all = WrittenFrames.ToArray();
        return index < all.Length ? all[index] : null;
    }

    /// <summary>Returns all written frames as an array.</summary>
    public byte[][] GetAllWrittenFrames() => WrittenFrames.ToArray();

    public void Dispose() => _isOpen = false;
}
