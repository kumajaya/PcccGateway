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
/// Transport abstraction for the gateway's CLIENT-FACING frontend — the side
/// that EIP clients such as RSLinx, libplctag and pycomm3 connect to.
///
/// Not to be confused with <see cref="ITransport"/>, which is the PLC-facing
/// backend. A PDU arriving on an IServerTransport is forwarded out through an
/// ITransport, and the PLC's reply travels back the same way in reverse.
///
/// EIPServerTransport is the only implementation: the frontend is always an
/// EtherNet/IP server, whichever backend --mode selects.
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
    ///
    /// The handler forwards the PDU to the PLC-side transport unchanged, and
    /// later routes the PLC's reply back through <see cref="SendResponse"/>
    /// using the <c>ClientContext</c> carried here. It does NOT interpret the
    /// PCCC payload — deciding what a command means is the PLC's job, and the
    /// gateway's transparency depends on it staying that way.
    /// </summary>
    event EventHandler<(byte[] pdu, object ClientContext)> PduReceived;

    /// <summary>
    /// Human-readable name of the transport for logging.
    /// </summary>
    string Name { get; }
}
