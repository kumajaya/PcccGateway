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
/// Transport abstraction for the PLC-facing backend — the side that reaches
/// the legacy PLC over DF1 serial, CSPv4, or EtherNet/IP.
///
/// A transport is responsible for sending and receiving inner PCCC frames
/// (PDUs) without any transport‑specific framing (e.g., no DLE stuffing,
/// no checksum, no CIP encapsulation).
///
/// Not to be confused with <see cref="IServerTransport"/>, which is the
/// client-facing frontend.
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
///
/// <para>
/// THREADING — <see cref="FrameReceived"/> is NOT raised on a single agreed
/// thread, and cannot be: the implementations differ by design, not by
/// oversight.
/// </para>
/// <list type="bullet">
///   <item>
///     DF1 full-duplex and the TCP transports raise it on a background
///     receive/executor thread. <see cref="SendFrame"/> returns before the
///     reply arrives, and the reply is correlated later by TNS.
///   </item>
///   <item>
///     DF1 half-duplex raises it on the caller's own thread, from inside
///     <see cref="SendFrame"/>, because a half-duplex master transaction is
///     synchronous: the poll and its response belong to the send. By the time
///     SendFrame returns, the handler has already run.
///   </item>
/// </list>
/// <para>
/// A subscriber must therefore be safe on either. It may call back into the
/// transport, but must not block waiting for further inbound frames.
/// </para>
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
    /// <remarks>
    /// The two failure exceptions mean different things and must not be
    /// conflated. <see cref="TimeoutException"/> says the link was up and the
    /// exchange did not complete within the configured timeout and retry policy
    /// — either nothing came back, or the peer answered but never accepted, as
    /// when it NAKs every attempt. Retrying may work.
    /// <see cref="InvalidOperationException"/> says this transport is not in a
    /// state to send at all, and retrying cannot help until it is reopened.
    /// </remarks>
    /// <param name="innerFrame">Inner PCCC frame (without transport framing).</param>
    /// <exception cref="TimeoutException">
    /// Thrown when the exchange does not complete within the configured timeout
    /// and retry policy — no acknowledgment arrived, or every attempt was NAK'd.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the transport is closed, closing, or disposed.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="innerFrame"/> is null or too short to carry
    /// a PCCC frame.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="innerFrame"/> is longer than this
    /// transport's encapsulation can express.
    /// </exception>
    void SendFrame(byte[] innerFrame);

    /// <summary>
    /// Raised when a complete, valid inner frame has been received and
    /// stripped of all transport‑specific framing and checksums.
    /// See the threading note on the interface itself.
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
