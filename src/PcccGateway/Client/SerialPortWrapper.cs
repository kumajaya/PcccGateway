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
using System.Threading.Channels;
using PcccGateway.Interface;

namespace PcccGateway.Client;

/// <summary>
/// Serial port wrapper with robust byte array handling and deadlock prevention.
/// </summary>
public class SerialPortWrapper : ISerialPort
{
    private readonly SerialPort _port;
    private readonly object _sync = new object();

    // Received chunks are handed off through this channel instead of being dispatched
    // straight from the SerialPort driver's own callback thread. Reading synchronously
    // there risks a deadlock if a handler calls back into the port (e.g. Close()) from
    // the same thread the driver uses to raise DataReceived. A single dedicated consumer
    // task drains the channel and invokes BytesReceived in the exact order chunks arrived
    // — unlike the previous ThreadPool.QueueUserWorkItem-per-chunk approach, where the
    // pool's own scheduling gave no guarantee that two work items would run in the order
    // they were queued, letting a later chunk of the same DF1/CSP stream reach the
    // consumer before an earlier one and corrupt frame reassembly.
    private readonly Channel<byte[]> _rxChannel = Channel.CreateUnbounded<byte[]>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
    private readonly Task _rxDispatchTask;

    public event EventHandler<byte[]>? BytesReceived;

    public int BaudRate => _port.BaudRate;

    public Parity Parity => _port.Parity;

    public SerialPortWrapper(string portName, int baudRate, Parity parity)
    {
        _port = new SerialPort(portName, baudRate, parity, 8, StopBits.One)
        {
            ReadTimeout = 2000,
            WriteTimeout = 2000
        };
        _port.DataReceived += Port_DataReceived;
        _rxDispatchTask = Task.Run(DispatchLoopAsync);
    }

    private void Port_DataReceived(object sender, SerialDataReceivedEventArgs e)
    {
        try
        {
            int toRead = _port.BytesToRead;
            if (toRead <= 0) return;

            byte[] buffer = new byte[toRead];
            int read = _port.Read(buffer, 0, toRead);

            if (read > 0)
            {
                // Crop buffer to actual bytes read
                byte[] actualData = new byte[read];
                Buffer.BlockCopy(buffer, 0, actualData, 0, read);

                // TryWrite on an unbounded channel never blocks and never fails
                // (short of the channel already being completed at shutdown), so this
                // returns immediately — the driver's callback thread is not held up
                // waiting for the handler to run.
                _rxChannel.Writer.TryWrite(actualData);
            }
        }
        catch
        {
            // Ignore serial port read errors; upper layer will timeout
        }
    }

    /// <summary>
    /// Drains <see cref="_rxChannel"/> on a single dedicated task, invoking
    /// <see cref="BytesReceived"/> for each chunk strictly in arrival order.
    /// Runs until <see cref="Dispose"/> completes the channel writer.
    /// </summary>
    private async Task DispatchLoopAsync()
    {
        try
        {
            await foreach (var chunk in _rxChannel.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                try
                {
                    BytesReceived?.Invoke(this, chunk);
                }
                catch
                {
                    // Ignore exceptions in event handlers (upper layer handles)
                }
            }
        }
        catch (ChannelClosedException)
        {
            // Normal shutdown path.
        }
    }

    public void Open()
    {
        lock (_sync)
        {
            if (!_port.IsOpen) _port.Open();
        }
    }

    public void Close()
    {
        lock (_sync)
        {
            if (_port.IsOpen) _port.Close();
        }
    }

    public void Write(byte[] buffer, int offset, int count)
    {
        lock (_sync)
        {
            if (_port.IsOpen)
            {
                _port.Write(buffer, offset, count);
            }
        }
    }

    public bool IsOpen
    {
        get { lock (_sync) { return _port.IsOpen; } }
    }

    public bool RtsEnable
    {
        get { lock (_sync) { return _port.RtsEnable; } }
        set { lock (_sync) { _port.RtsEnable = value; } }
    }

    public bool DtrEnable
    {
        get { lock (_sync) { return _port.DtrEnable; } }
        set { lock (_sync) { _port.DtrEnable = value; } }
    }

    public void Dispose()
    {
        try
        {
            _port.DataReceived -= Port_DataReceived;
            Close();
            _port.Dispose();
        }
        catch { }

        // Signal the dispatch loop to exit once it has drained whatever was already
        // queued, then wait briefly for it to finish so BytesReceived is never invoked
        // after Dispose() returns. Bounded wait: a stuck subscriber must not hang shutdown.
        try
        {
            _rxChannel.Writer.TryComplete();
            _rxDispatchTask.Wait(2000);
        }
        catch { }
    }
}
