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

using System.IO.Ports;

namespace PcccGateway.Interface;

/// <summary>
/// Abstraction for serial port operations to enable unit testing.
///
/// <para>
/// Two implementations ship here and they sit on opposite sides of the same
/// interface: <c>SerialPortWrapper.SystemSerialPort</c> wraps a real
/// <see cref="SerialPort"/>, while <c>SerialPortWrapper</c> itself both
/// implements ISerialPort and consumes one — it is a decorator that moves
/// callbacks off the driver's thread and scopes them to a session.
/// </para>
/// </summary>
/// <remarks>
/// The receive path carries obligations that were previously written down only
/// in the consumer, where an implementer would never look for them. Anyone
/// implementing this interface must honour all three.
///
/// <list type="bullet">
///   <item>
///     BUFFER OWNERSHIP — the array passed to <see cref="BytesReceived"/> need
///     only stay valid for the duration of that synchronous call. An
///     implementation may reuse or mutate it afterwards, so a subscriber that
///     defers processing must take its own copy. SerialPortWrapper clones for
///     exactly this reason.
///   </item>
///   <item>
///     THREADING — <see cref="BytesReceived"/> is raised on whatever thread the
///     underlying driver uses; for <see cref="SerialPort"/> that is a pool
///     thread, and it is not guaranteed to be the same one each time. Chunks
///     are delivered in arrival order, and a handler must not assume otherwise.
///   </item>
///   <item>
///     HANDLERS MUST NOT BLOCK — a handler runs on the thread that would
///     otherwise be reading the port. One that waits for more inbound bytes
///     waits for bytes only it could receive. Offload anything that blocks.
///   </item>
/// </list>
/// </remarks>
public interface ISerialPort : IDisposable
{
    /// <summary>
    /// Raised for each chunk of bytes received. See the interface remarks for
    /// buffer ownership, threading, and the no-blocking requirement.
    /// </summary>
    event EventHandler<byte[]>? BytesReceived;

    /// <summary>True when the port is open and usable.</summary>
    bool IsOpen { get; }

    /// <summary>Opens the port. Throws if it cannot be opened.</summary>
    void Open();

    /// <summary>
    /// Closes the port. Must be safe to call when already closed, and must not
    /// throw for that reason alone.
    /// </summary>
    void Close();

    /// <summary>
    /// Writes bytes to the port. Throws <see cref="InvalidOperationException"/>
    /// when the port is not open.
    /// </summary>
    void Write(byte[] buffer, int offset, int count);

    /// <summary>RS-485 direction control via the RTS line.</summary>
    bool RtsEnable { get; set; }

    /// <summary>RS-485 direction control via the DTR line.</summary>
    bool DtrEnable { get; set; }

    /// <summary>Configured line rate. Set at construction; not changeable here.</summary>
    int BaudRate { get; }

    /// <summary>Configured parity. Set at construction; not changeable here.</summary>
    Parity Parity { get; }

    // No Read or BytesToRead. Every receive path in the gateway is event-driven
    // through BytesReceived; nothing ever polled the port through this interface,
    // and the three implementations had drifted into three different answers for
    // a closed port without anything noticing. Reading still happens, inside
    // SystemSerialPort's DataReceived handler, against the concrete SerialPort —
    // it simply never went through this abstraction.
}
