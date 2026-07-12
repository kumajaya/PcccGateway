using PcccGateway.Client;
using PcccGateway.Common;
using Xunit;

namespace PcccGateway.Tests;

/// <summary>
/// Tests for <see cref="DF1BaseTransport.CalculateChecksum"/> (CRC-16 and BCC).
/// </summary>
public class ChecksumTests
{
    // ── BCC: two's-complement of the modulo-256 sum. Expected values are
    //    computed by hand so the test pins the exact algorithm. ──
    [Theory]
    [InlineData(new byte[] { 0x00 }, 0x00)]
    [InlineData(new byte[] { 0xFF }, 0x01)]
    [InlineData(new byte[] { 0x01, 0x02 }, 0xFD)]          // 256-3
    [InlineData(new byte[] { 0x10, 0x20, 0x30 }, 0xA0)]    // 256-0x60
    public void Bcc_MatchesHandComputedValue(byte[] data, int expected)
    {
        ushort bcc = DF1BaseTransport.CalculateChecksum(data, CheckSumOptions.Bcc);
        Assert.Equal((ushort)expected, bcc);
    }

    // ── CRC-16: cross-check the table-driven implementation against an
    //    independent bit-by-bit reference (reflected poly 0xA001, init 0x0000,
    //    with the ETX byte folded in as per the AB DF1 spec). ──
    [Theory]
    [InlineData(new byte[] { 0x01, 0x00, 0x0F, 0x00, 0x10, 0x00 })]
    [InlineData(new byte[] { 0x00 })]
    [InlineData(new byte[] { 0x10, 0x10, 0x02, 0x03 })]
    [InlineData(new byte[] { 0xAA, 0x55, 0x12, 0x34, 0x56, 0x78, 0x9A })]
    public void Crc_MatchesBitwiseReference(byte[] data)
    {
        ushort table = DF1BaseTransport.CalculateChecksum(data, CheckSumOptions.Crc);
        Assert.Equal(ReferenceCrc(data), table);
    }

    [Fact]
    public void Crc_IsDeterministicAndSensitive()
    {
        byte[] a = { 0x01, 0x02, 0x03 };
        byte[] b = { 0x01, 0x02, 0x04 };
        Assert.Equal(
            DF1BaseTransport.CalculateChecksum(a, CheckSumOptions.Crc),
            DF1BaseTransport.CalculateChecksum(a, CheckSumOptions.Crc));   // deterministic
        Assert.NotEqual(
            DF1BaseTransport.CalculateChecksum(a, CheckSumOptions.Crc),
            DF1BaseTransport.CalculateChecksum(b, CheckSumOptions.Crc));   // sensitive
    }

    /// <summary>Independent bit-by-bit CRC-16 (reflected 0xA001, init 0), ETX folded.</summary>
    private static ushort ReferenceCrc(byte[] data)
    {
        ushort crc = 0x0000;
        foreach (byte x in AppendEtx(data))
        {
            crc ^= x;
            for (int i = 0; i < 8; i++)
                crc = (ushort)((crc & 1) != 0 ? (crc >> 1) ^ 0xA001 : crc >> 1);
        }
        return crc;
    }

    private static IEnumerable<byte> AppendEtx(byte[] data)
    {
        foreach (byte b in data) yield return b;
        yield return 0x03; // ETX, per AB DF1
    }
}
