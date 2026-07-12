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
/// Transport abstraction for PCCC emulator link layer implementations.
/// Supports DF1 Full-Duplex (serial), EtherNet/IP (EIP/PCCC), and future DH485.
/// </summary>
public interface IServerTransport
{
    /// <summary>
    /// Starts the transport handler (opens serial port, starts listener, etc.)
    /// </summary>
    void Start();

    /// <summary>
    /// Stops the transport handler gracefully.
    /// </summary>
    void Stop();

    /// <summary>
    /// Sends a response PDU back to the client using this transport's framing.
    /// The PDU is the inner frame (DST, SRC, CMD, STS, TNS, FUNC, DATA...)
    /// </summary>
    /// <param name="pdu">Inner frame PDU to send</param>
    /// <param name="clientContext">Client context object (e.g., EIPClient instance) for routing response to correct client.
    /// For single-client transports like DF1 serial, this parameter is ignored.</param>
    void SendResponse(byte[] pdu, object clientContext);

    /// <summary>
    /// Raised when a complete PDU (inner frame) has been received and parsed.
    /// The handler should dispatch the command to PlcMemory.
    /// </summary>
    event EventHandler<(byte[] pdu, object ClientContext)> PduReceived;

    /// <summary>
    /// Human-readable name of the transport for logging.
    /// </summary>
    string Name { get; }
}
