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

namespace PcccGateway.Interface;

/// <summary>
/// Transport abstraction for the PCCC application layer.
/// A transport is responsible for sending and receiving inner PCCC frames
/// (PDUs) without any transport‑specific framing (e.g., no DLE stuffing,
/// no checksum, no CIP encapsulation).
/// </summary>
/// <remarks>
/// This interface allows the same PCCC logic to operate over DF1 serial,
/// EtherNet/IP (CIP), DH485, or any future transport.
/// Implementations must handle all low‑level details:
/// <list type="bullet">
///   <item>Opening and closing the communication channel</item>
///   <item>Adding transport‑specific framing and checksums</item>
///   <item>Waiting for acknowledgments (ACK/NAK, CIP general status)</item>
///   <item>Raising <see cref="FrameReceived"/> when a complete, valid inner frame arrives</item>
/// </list>
/// </remarks>
public interface ITransport : IDisposable
{
    /// <summary>
    /// Opens the communication channel (serial port, TCP connection, etc.).
    /// </summary>
    void Open();

    /// <summary>
    /// Closes the communication channel and releases any associated resources.
    /// </summary>
    void Close();

    /// <summary>
    /// Sends an inner PCCC frame to the remote device.
    /// The frame must be in the standard PCCC format:
    /// [DST, SRC, CMD, STS, TNS_LO, TNS_HI, FUNC (optional), DATA...].
    /// </summary>
    /// <param name="innerFrame">Inner PCCC frame (without transport framing).</param>
    /// <exception cref="TimeoutException">Thrown when no acknowledgment is received within the timeout.</exception>
    void SendFrame(byte[] innerFrame);

    /// <summary>
    /// Raised when a complete, valid inner frame has been received and
    /// stripped of all transport‑specific framing and checksums.
    /// </summary>
    event EventHandler<byte[]> FrameReceived;

    /// <summary>
    /// Raised when a raw transport frame is sent (before any processing).
    /// </summary>
    event EventHandler<byte[]>? RawFrameSent;

    /// <summary>
    /// Raised when a raw transport frame is received (before any processing).
    /// </summary>
    event EventHandler<byte[]>? RawFrameReceived;

    /// <summary>
    /// Indicates whether the transport is open and ready for communication.
    /// </summary>
    bool IsOpen { get; }
}
