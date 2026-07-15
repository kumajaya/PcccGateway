using PcccGateway.Interface;
using Xunit;

namespace PcccGateway.Tests;

/// <summary>
/// Tests for <see cref="Gateway"/>'s TNS correlation mechanism.
/// Verifies unique TNS allocation, circuit breaker, and eviction logic.
/// These tests do NOT call <see cref="Gateway.Start()"/> to avoid background
/// tasks (like <c>TryDiscoverIdentity</c>) from consuming TNS values
/// and interfering with the test state.
/// </summary>
public class GatewayTnsTests
{
    private sealed class DummyTransport : ITransport
    {
        public bool IsOpen => false;
        public event EventHandler<byte[]>? FrameReceived { add { } remove { } }
        public event EventHandler<byte[]>? RawFrameSent { add { } remove { } }
        public event EventHandler<byte[]>? RawFrameReceived { add { } remove { } }
        public void Open() { }
        public void Close() { }
        public void SendFrame(byte[] innerFrame) { }
        public void Dispose() { }
    }

    private Gateway CreateGateway() => new Gateway(new DummyTransport());

    [Fact]
    public void AllocateGatewayTns_ReturnsUniqueTns_ForMultipleRequests()
    {
        var gateway = CreateGateway();

        var tnsSet = new HashSet<ushort>();

        for (int i = 0; i < 1000; i++)
        {
            var context = new object();
            var tns = gateway.AllocateGatewayTns(context, (ushort)i);
            Assert.True(tnsSet.Add(tns), $"Duplicate TNS 0x{tns:X4} allocated at iteration {i}");
        }
    }

    [Fact]
    public void AllocateGatewayTns_ThrowsInvalidOperationException_WhenPoolExhausted()
    {
        var gateway = CreateGateway();

        // Allocate 65535 TNS values to exhaust the pool.
        for (int i = 0; i < 65535; i++)
        {
            var context = new object();
            gateway.AllocateGatewayTns(context, (ushort)i);
        }

        // The next allocation should throw because the pool is full.
        var ex = Assert.Throws<InvalidOperationException>(() =>
            gateway.AllocateGatewayTns(new object(), 0));
        Assert.Contains("exhausted", ex.Message);
    }

    [Fact]
    public void EvictStale_RemovesExpiredEntries()
    {
        var gateway = CreateGateway();
        gateway.PendingTimeoutMs = 100;

        var context = new object();
        gateway.AllocateGatewayTns(context, 0x1234);

        // Verify the entry was added.
        Assert.Single(gateway._pending);

        // Wait for the entry to expire.
        Thread.Sleep(200);

        // Evict stale entries.
        gateway.EvictStale();

        // Verify the entry was removed.
        Assert.Empty(gateway._pending);
    }

    [Fact]
    public void EvictStale_DoesNotRemoveNewerRequestWithSameTns()
    {
        // This test verifies that TryRemove(KeyValuePair) prevents accidental
        // eviction of a newer request that reuses the same TNS value.
        // We simulate this by: allocate TNS → expire → allocate new request
        // with the same value → evict again → verify the new request remains.

        var gateway = CreateGateway();
        gateway.PendingTimeoutMs = 500;

        // Allocate a TNS and let it expire.
        var context1 = new object();
        var tns1 = gateway.AllocateGatewayTns(context1, 0x1234);
        Assert.Single(gateway._pending);

        Thread.Sleep(600);
        gateway.EvictStale();
        Assert.Empty(gateway._pending);

        // Force the internal counter to wrap around to exactly before tns1.
        // This simulates 65,535 other requests happening in the meantime.
        gateway._tnsCounter = (int)tns1 - 1;

        // Allocate a new request. It will now naturally reuse the same TNS value.
        var context2 = new object();
        var tns2 = gateway.AllocateGatewayTns(context2, 0x1234);
        Assert.Equal(tns1, tns2);
        Assert.Single(gateway._pending);

        // Evict again — since this new entry hasn't expired, it MUST NOT be removed.
        gateway.EvictStale();

        // The newer request should still be present.
        Assert.Single(gateway._pending);
    }
}
