using PcccGateway;
using Xunit;

namespace PcccGateway.Tests;

/// <summary>
/// Tests for <see cref="Gateway.ResolveIdentity"/> — mapping a PCCC Get Diagnostic
/// Status payload to a CIP identity. Payloads for PLC-5/40E and MicroLogix 1400 are
/// taken from real hardware captures.
/// </summary>
public class IdentityResolverTests
{
    // Real PLC-5/40E Get Diagnostic Status DATA (Wireshark capture).
    private static readonly byte[] Plc5_40E =
    {
        0x06, 0xEB, 0x4B, 0x00, 0x80, 0x01, 0x00, 0xA0,
        0xB8, 0xFD, 0x00, 0xC9, 0x00, 0x36, 0x00, 0x04,
    };

    // Real MicroLogix 1400 Get Diagnostic Status DATA (gateway trace); "1766-LEC".
    private static readonly byte[] Ml1400 =
    {
        0x00, 0xEE, 0x4A, 0x9F, 0x23, 0x31, 0x37, 0x36,
        0x36, 0x2D, 0x4C, 0x45, 0x43, 0x20, 0x20, 0x20,
    };

    [Fact]
    public void Plc5_40E_ResolvesToProductCode23()
    {
        var id = Gateway.ResolveIdentity(Plc5_40E);
        Assert.NotNull(id);
        Assert.Equal((ushort)14, id!.Value.DeviceType);
        Assert.Equal((ushort)23, id.Value.ProductCode);
        Assert.Equal("PLC-5/40E", id.Value.Name);
    }

    [Fact]
    public void MicroLogix1400_ResolvesToProductCode90()
    {
        var id = Gateway.ResolveIdentity(Ml1400);
        Assert.NotNull(id);
        Assert.Equal((ushort)14, id!.Value.DeviceType);
        Assert.Equal((ushort)90, id.Value.ProductCode);
        Assert.Equal("MicroLogix 1400", id.Value.Name);
    }

    [Fact]
    public void Slc505_TypeVariant_ResolvesToCode20()
    {
        // SLC/ML family (0xEE), processor type 0x14 → SLC 5/05, Code 20.
        byte[] p = { 0x00, 0xEE, 0x34, 0x14, 0x32, 0x35, 0x2F, 0x30, 0x35, 0x20 };
        var id = Gateway.ResolveIdentity(p);
        Assert.Equal((ushort)14, id!.Value.DeviceType);
        Assert.Equal((ushort)20, id.Value.ProductCode);
    }

    // Regression: the PLC-5 expansion byte and SLC/ML processor type share values
    // (0x15 = PLC-5/40B on a PLC-5, but an SLC 5/05 variant on an SLC). A PLC-5 with
    // expansion 0x15 must resolve within the PLC-5 family (fallback PLC-5/40E), never
    // cross into the SLC table's 0x15 entry.
    [Fact]
    public void Plc5_With0x15_DoesNotCrossIntoSlcTable()
    {
        byte[] p = { 0x06, 0xEB, 0x15, 0x00, 0x00, 0x00 }; // PLC-5 family, expansion 0x15
        var id = Gateway.ResolveIdentity(p);
        Assert.Equal((ushort)14, id!.Value.DeviceType);
        Assert.Equal((ushort)23, id.Value.ProductCode);   // PLC-5/40E fallback, NOT SLC code 21
        Assert.Equal("PLC-5", id.Value.Name);
    }

    [Fact]
    public void UnknownSlc_FallsBackToSlc505WithReportedCatalog()
    {
        // SLC/ML family, unknown type 0xF0, catalog "1747-XYZ".
        byte[] p =
        {
            0x00, 0xEE, 0x34, 0xF0, 0x00,
            0x31, 0x37, 0x34, 0x37, 0x2D, 0x58, 0x59, 0x5A,
        };
        var id = Gateway.ResolveIdentity(p);
        Assert.Equal((ushort)14, id!.Value.DeviceType);
        Assert.Equal((ushort)20, id.Value.ProductCode);   // SLC 5/05 identity
        Assert.Equal("1747-XYZ", id.Value.Name);          // display name from the PLC
    }

    [Fact]
    public void UnknownPlc5_FallsBackToPlc540E()
    {
        byte[] p = { 0x06, 0xEB, 0x99, 0x00, 0x00, 0x00 }; // PLC-5 family, unknown expansion
        var id = Gateway.ResolveIdentity(p);
        Assert.Equal((ushort)14, id!.Value.DeviceType);
        Assert.Equal((ushort)23, id.Value.ProductCode);
        Assert.Equal("PLC-5", id.Value.Name);
    }

    [Fact]
    public void TooShortPayload_ReturnsNull()
    {
        Assert.Null(Gateway.ResolveIdentity(new byte[] { 0x00, 0xEE, 0x34, 0x9F }));
    }
}
