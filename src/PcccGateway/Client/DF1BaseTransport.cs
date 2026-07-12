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

using PcccGateway.Common;
using PcccGateway.Interface;

namespace PcccGateway.Client;

/// <inheritdoc cref="ITransport"/>
/// <summary>
/// Abstract base class for DF1 transport implementations (full‑duplex and half‑duplex master).
/// Provides common DF1 framing services: DLE stuffing, checksum calculation, control byte
/// transmission, and raw frame events. Derived classes must implement <see cref="SendFrame"/>.
/// </summary>
public abstract class DF1BaseTransport : ITransport
{
    // --- DF1 control characters (Publication 1770-6.5.16, Chapter 5) ---
    /// <summary>Data Link Escape (0x10).</summary>
    protected const byte DLE = 0x10;
    /// <summary>Start of Text (0x02).</summary>
    protected const byte STX = 0x02;
    /// <summary>End of Text (0x03).</summary>
    protected const byte ETX = 0x03;
    /// <summary>Acknowledge (0x06).</summary>
    protected const byte ACK = 0x06;
    /// <summary>Not Acknowledge (0x15).</summary>
    protected const byte NAK = 0x15;
    /// <summary>Enquiry (0x05).</summary>
    protected const byte ENQ = 0x05;

    // --- Common fields ---
    /// <summary>Serial port abstraction.</summary>
    protected readonly ISerialPort _port;

    private CheckSumOptions _checksumType = CheckSumOptions.Crc;
    private int _sleepDelay = 0;
    private int _maxTicks = 100;      // 100 * 20ms = 2 seconds

    /// <inheritdoc/>
    public event EventHandler<byte[]>? FrameReceived;

    /// <inheritdoc/>
    public event EventHandler<byte[]>? RawFrameSent;

    /// <inheritdoc/>
    public event EventHandler<byte[]>? RawFrameReceived;

    /// <inheritdoc/>
    public bool IsOpen => _port.IsOpen;

    /// <summary>Gets or sets the checksum algorithm (CRC or BCC).</summary>
    public CheckSumOptions ChecksumType
    {
        get => _checksumType;
        set => _checksumType = value;
    }

    /// <summary>
    /// Sleep delay (ms) added after a NAK. Increases automatically on repeated NAKs.
    /// Helps stabilise communication with USB‑to‑serial converters.
    /// </summary>
    public int SleepDelay
    {
        get => _sleepDelay;
        set => _sleepDelay = value < 0 ? 0 : value;
    }

    /// <summary>
    /// Maximum number of polling ticks (each tick = 20 ms) to wait for ACK/NAK.
    /// Default is 100 (2 seconds). Used in auto‑detect and normal sends.
    /// </summary>
    public int MaxTicks
    {
        get => _maxTicks;
        set => _maxTicks = value > 0 ? value : 100;
    }

    /// <summary>
    /// Initialises the base DF1 transport with a custom <see cref="ISerialPort"/>.
    /// </summary>
    protected DF1BaseTransport(ISerialPort port)
    {
        _port = port ?? throw new ArgumentNullException(nameof(port));
    }

    /// <summary>
    /// Initialises the base DF1 transport with standard serial port parameters.
    /// </summary>
    protected DF1BaseTransport(string portName, int baudRate, System.IO.Ports.Parity parity)
        : this(new SerialPortWrapper(portName, baudRate, parity))
    {
    }

    /// <inheritdoc/>
    public virtual void Open() => _port.Open();

    /// <inheritdoc/>
    public virtual void Close() => _port.Close();

    /// <inheritdoc/>
    public abstract void SendFrame(byte[] innerFrame);

    /// <summary>
    /// Applies DLE stuffing to a payload: every 0x10 byte is duplicated.
    /// </summary>
    protected internal static byte[] ApplyDleStuffing(byte[] payload)
    {
        var result = new List<byte>(payload.Length * 2);
        foreach (byte b in payload)
        {
            result.Add(b);
            if (b == DLE)
                result.Add(DLE);
        }
        return result.ToArray();
    }

    /// <summary>
    /// Removes DLE stuffing from a stuffed payload.
    /// </summary>
    protected internal static byte[] RemoveDleStuffing(byte[] stuffed)
    {
        var result = new List<byte>(stuffed.Length);
        for (int i = 0; i < stuffed.Length; i++)
        {
            if (stuffed[i] == DLE && i + 1 < stuffed.Length && stuffed[i + 1] == DLE)
            {
                result.Add(DLE);
                i++; // skip the stuffed duplicate
            }
            else
                result.Add(stuffed[i]);
        }
        return result.ToArray();
    }

    /// <summary>
    /// Sends a single DF1 control byte (ACK, NAK, or ENQ) prefixed with DLE.
    /// </summary>
    protected void SendControl(byte controlByte)
    {
        if (controlByte != ACK && controlByte != NAK && controlByte != ENQ)
            throw new ArgumentException("Invalid control byte.", nameof(controlByte));
        var frame = new byte[] { DLE, controlByte };
        _port.Write(frame, 0, frame.Length);
    }

    /// <summary>
    /// Builds a complete wire frame from an inner PCCC frame.
    /// Performs DLE stuffing and appends the checksum (CRC or BCC).
    /// </summary>
    protected byte[] BuildWireFrame(byte[] innerFrame)
    {
        // 1. DLE stuffing
        byte[] stuffed = ApplyDleStuffing(innerFrame);

        // 2. Calculate checksum over the UNSTUFFED inner frame
        ushort checksum = CalculateChecksum(innerFrame, _checksumType);
        int csLen = (_checksumType == CheckSumOptions.Crc) ? 2 : 1;

        // 3. Build: DLE STX + stuffed + DLE ETX + checksum
        byte[] frame = new byte[2 + stuffed.Length + 2 + csLen];
        int idx = 0;
        frame[idx++] = DLE;
        frame[idx++] = STX;
        Array.Copy(stuffed, 0, frame, idx, stuffed.Length);
        idx += stuffed.Length;
        frame[idx++] = DLE;
        frame[idx++] = ETX;
        frame[idx++] = (byte)(checksum & 0xFF);
        if (csLen == 2)
            frame[idx++] = (byte)((checksum >> 8) & 0xFF);
        return frame;
    }

    /// <summary>Raises the <see cref="FrameReceived"/> event.</summary>
    protected virtual void OnFrameReceived(byte[] innerFrame)
    {
        FrameReceived?.Invoke(this, innerFrame);
    }

    /// <summary>Raises the <see cref="RawFrameSent"/> event.</summary>
    protected virtual void OnRawFrameSent(byte[] rawFrame)
    {
        RawFrameSent?.Invoke(this, rawFrame);
    }

    /// <summary>Raises the <see cref="RawFrameReceived"/> event.</summary>
    protected virtual void OnRawFrameReceived(byte[] rawFrame)
    {
        RawFrameReceived?.Invoke(this, rawFrame);
    }

    // ─── CRC-16 lookup table (standard DF1 CRC-16, AB Pub 1770-6.5.16) ────────────────────────
    private static readonly ushort[] CRC16Table =
    {
        0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
        0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
        0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
        0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
        0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
        0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
        0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
        0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
        0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
        0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
        0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
        0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
        0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
        0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
        0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
        0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
        0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
        0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
        0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
        0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
        0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
        0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
        0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
        0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
        0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
        0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
        0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
        0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
        0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
        0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
        0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
        0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
    };

    // ─── Checksum ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Calculates CRC-16 or BCC checksum over the given data.
    /// For CRC, the ETX byte (0x03) is appended as per AB spec.
    /// </summary>
    public static ushort CalculateChecksum(byte[] data, CheckSumOptions option)
    {
        if (option == CheckSumOptions.Crc)
        {
            ushort crc = 0x0000; // AB DF1 init value — NOT Modbus 0xFFFF
            foreach (byte b in data)
            {
                byte t = (byte)((crc & 0xFF) ^ b);
                crc = (ushort)((crc >> 8) ^ CRC16Table[t]);
            }
            // Include ETX (0x03) as per AB specification
            byte etx = (byte)((crc & 0xFF) ^ 0x03);
            crc = (ushort)((crc >> 8) ^ CRC16Table[etx]);
            return crc;
        }
        else
        {
            // BCC: two's complement of the modulo-256 sum (AB DF1, Pub 1770-6.5.16)
            int sum = 0;
            foreach (byte b in data) sum += b;
            sum = sum & 0xFF;
            return (ushort)((0x100 - sum) & 0xFF);
        }
    }

    /// <inheritdoc/>
    public virtual void Dispose()
    {
        _port.Dispose();
    }
}
