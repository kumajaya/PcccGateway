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
using System.Runtime.ExceptionServices;
using PcccGateway.Common;
using PcccGateway.Interface;

namespace PcccGateway.Client;

/// <summary>
/// DF1 half‑duplex master transport for RS‑485 multi‑drop networks.
/// Implements the correct 5‑step transaction sequence per Allen‑Bradley
/// Publication 1770-6.5.16, Chapter 6.
/// 
/// Correct transaction sequence:
///   1. Master sends command frame (DLE STX ... DLE ETX + checksum).
///   2. Slave responds with DLE ACK (link‑layer acknowledgment).
///   3. Master enters polling loop: sends DLE ENQ + SlaveAddress repeatedly.
///   4. Slave responds:
///      - DLE NAK if not ready → master continues polling.
///      - Data frame (DLE STX ...) when ready → master proceeds.
///   5. Master sends final DLE ACK and raises FrameReceived event.
/// 
/// This transport is synchronous and thread‑safe. Only one transaction
/// can be active at a time.
/// </summary>
/// <remarks>
/// Re-entrancy: handlers of both events MAY call <see cref="SendFrame"/>
/// synchronously, by two different routes.
///
/// <see cref="ITransport.FrameReceived"/> and the response's raw frame are
/// raised by <see cref="SendFrame"/> itself, on the caller's own thread, after
/// _txLock has been released — so a handler is free to call back in, and
/// SendFrame still guarantees the response has been delivered by the time it
/// returns. Frames NOT claimed by a transaction are posted through
/// PostRawFrameReceived to the callback executor DF1BaseTransport owns, which is
/// a different thread from the one parsing inbound bytes.
///
/// (Before that executor existed, those unclaimed frames were raised inline on
/// the serial callback thread, and a handler calling SendFrame there starved the
/// parsing of the very ACK it waited for. DF1CallbackReentrancyTests covers it.)
///
/// Two limits remain. The executor is single-threaded, so a blocking handler
/// delays every later callback — order is preserved, latency is not. And
/// Close() from a handler is safe in both routes because neither of them runs
/// on SerialPortWrapper's callback thread: the executor owns one, SendFrame's
/// caller owns the other. That thread therefore never holds the wrapper's
/// callback lease it would have to wait for.
///
/// (Before the executor existed, safety did rest on the wrapper skipping that
/// lease when the caller was its own callback thread. That is no longer the
/// reason — the lease is not even contended now. DF1CallbackReentrancyTests
/// records the change.)
/// </remarks>
public class DF1HalfDuplexTransport : DF1BaseTransport
{
    // --- RS-485 Direction Control ---
    /// <summary>
    /// RS-485 direction control mode.
    /// </summary>
    public enum Rs485ControlMode
    {
        /// <summary>Auto‑direction (hardware handles RTS).</summary>
        Auto,
        /// <summary>Manual control using RTS pin.</summary>
        Rts,
        /// <summary>Manual control using DTR pin.</summary>
        Dtr
    }

    private Rs485ControlMode _rs485Mode = Rs485ControlMode.Auto;
    private int _rtsAssertDelayMs = 1;
    private int _rtsDeassertDelayMs = 5;   // Increased for safety margin

    /// <summary>
    /// Gets or sets the RS-485 direction control mode. Default is Auto.
    /// </summary>
    public Rs485ControlMode Rs485Mode
    {
        get => _rs485Mode;
        set => _rs485Mode = value;
    }

    /// <summary>
    /// Delay in milliseconds after asserting RTS/DTR before writing data.
    /// Typical value 1-5 ms. Used only when Rs485Mode is not Auto.
    /// </summary>
    public int RtsAssertDelayMs
    {
        get => _rtsAssertDelayMs;
        set => _rtsAssertDelayMs = Math.Max(0, value);
    }

    /// <summary>
    /// Delay in milliseconds after writing data before deasserting RTS/DTR.
    /// Typical value 2-10 ms. Used only when Rs485Mode is not Auto.
    /// </summary>
    public int RtsDeassertDelayMs
    {
        get => _rtsDeassertDelayMs;
        set => _rtsDeassertDelayMs = Math.Max(0, value);
    }

    // --- Slave addressing ---
    private int _slaveAddress = 1;
    private readonly object _txLock = new object();
    // Serialises the whole Open()/Close()/Dispose() lifecycle transition so a
    // concurrent Open() cannot clear _closing / reset _shutdownEvent in the
    // middle of a Close() still tearing the port down. Always the OUTERMOST lock.
    private readonly object _lifecycleLock = new object();

    /// <summary>
    /// Gets or sets the slave node address (1-254). Default is 1.
    /// </summary>
    public int SlaveAddress
    {
        get => _slaveAddress;
        set
        {
            if (value < 1 || value > 254)
                throw new ArgumentOutOfRangeException(nameof(SlaveAddress), "Address must be 1-254.");
            _slaveAddress = value;
        }
    }

    // --- Timeout Configuration ---
    /// <summary>
    /// Timeout in milliseconds waiting for the initial ACK after sending a command frame.
    /// Default is 500 ms.
    /// </summary>
    public int CommandAckTimeoutMs { get; set; } = 500;

    /// <summary>
    /// Timeout in milliseconds waiting for a response (NAK or data frame) to each poll.
    /// Default is 200 ms.
    /// </summary>
    public int PollResponseTimeoutMs { get; set; } = 200;

    /// <summary>
    /// Maximum number of poll attempts after receiving the initial ACK.
    /// Default is 20.
    /// </summary>
    public int MaxPollAttempts { get; set; } = 20;

    /// <summary>
    /// Delay in milliseconds between poll attempts when slave responds with NAK.
    /// Default is 20 ms.
    /// </summary>
    public int PollRetryDelayMs { get; set; } = 20;

    /// <summary>
    /// When true, bytes transmitted by this master are expected to echo back
    /// on the RX line (common on RS-485 half-duplex without hardware echo cancellation).
    /// The transport will discard echoed bytes automatically.
    /// Default is false (assumes hardware or adapter handles echo suppression).
    /// </summary>
    public bool EchoSuppression { get; set; } = false;

    // --- Explicit state machine for receive processing ---
    private enum MasterState
    {
        Idle,
        WaitingForCommandAck,   // After sending command frame, expecting ACK
        WaitingForPollResponse  // After sending poll, expecting NAK or data frame
    }
    private volatile MasterState _currentState = MasterState.Idle;
    private readonly object _stateLock = new object();

    // --- Receive buffers and flags ---
    private readonly object _rxLock = new object();
    private readonly RingBuffer _rxBuffer;
    private DateTime _frameStartTime = DateTime.MinValue;
    private const int FrameTimeoutMs = 500;
    private const int MaxBufferBytes = 4096;

    // Echo suppression. Both fields move together under _echoLock: the send path
    // arms them while the receive thread consumes them, and the old Interlocked
    // pairing was not enough — the count was read once to compare and again to
    // clamp, so a chunk arriving between those reads could drive it negative and
    // leave suppression stuck on.
    private readonly object _echoLock = new object();
    private int _echoSuppressBytes = 0;
    private bool _suppressEcho = false;

    // Transaction flags (volatile for cross-thread visibility)
    private volatile bool _commandAckReceived;
    private volatile bool _commandNakReceived;
    private volatile bool _pollNakReceived;
    private volatile bool _responseDataReceived;
    private volatile byte[]? _responseDataFrame;
    // Raw wire bytes of the response frame, handed to SendFrame() so it can raise
    // OnRawFrameReceived immediately before OnFrameReceived (raw-before-decoded
    // order). If the receive thread raised it instead, it would race the woken
    // SendFrame thread and could emit the decoded frame first.
    private volatile byte[]? _responseRawFrame;

    // Set by Close()/Dispose() so the polling wait loops exit promptly on shutdown.
    private volatile bool _closing;
    private volatile bool _disposing;

    // --- Event-based waiting (replaces tight polling) ---
    // Used to wake the sending thread when an ACK/NAK or data frame arrives.
    private readonly ManualResetEventSlim _stateEvent = new ManualResetEventSlim(false);
    private readonly ManualResetEventSlim _shutdownEvent = new ManualResetEventSlim(false);
    private int _activeOperations;

    /// <summary>
    /// Initialises the half‑duplex master transport with a custom <see cref="ISerialPort"/>.
    /// </summary>
    public DF1HalfDuplexTransport(ISerialPort port) : base(port)
    {
        _rxBuffer = new RingBuffer(MaxBufferBytes);
        _port.BytesReceived += OnBytesReceived;
    }

    /// <summary>
    /// Initialises the half‑duplex master transport with standard serial port parameters.
    /// </summary>
    public DF1HalfDuplexTransport(string portName, int baudRate, Parity parity)
        : base(portName, baudRate, parity)
    {
        _rxBuffer = new RingBuffer(MaxBufferBytes);
        _port.BytesReceived += OnBytesReceived;
    }

    /// <inheritdoc/>
    public override void Open()
    {
        // Serialise the whole transition with Close()/Dispose() so a concurrent
        // Close() cannot interleave and leave the port closed with _closing == false.
        lock (_lifecycleLock)
        {
            lock (_txLock)
            {
                if (_disposing)
                    throw new ObjectDisposedException(nameof(DF1HalfDuplexTransport));

                // Reset lifecycle/transaction state so nothing from the previous
                // session leaks into the new one.
                lock (_stateLock)
                {
                    // _closing is cleared only after base.Open() succeeds (below).
                    _shutdownEvent.Reset();
                    _stateEvent.Reset();
                    ResetTransactionFlags();
                    _currentState = MasterState.Idle;
                }

                // Reset receive state: a partial frame or stale frame-timing left
                // by the previous session would otherwise combine with new-session
                // bytes into an invalid frame and lose the first response.
                lock (_rxLock)
                {
                    _rxBuffer.Clear();
                    _frameStartTime = DateTime.MinValue;
                }

                // Reset echo suppression counters, under the lock that now owns
                // them — a stale count from the previous session would otherwise
                // eat the first bytes of this one.
                lock (_echoLock)
                {
                    _echoSuppressBytes = 0;
                    _suppressEcho = false;
                }

                // Clear _closing only AFTER the port opens successfully. If
                // base.Open() throws, the transport must stay closed so later
                // sends observe the failed lifecycle instead of writing to a port
                // that never opened.
                try
                {
                    base.Open();

                    // Set initial RTS/DTR state to receive mode BEFORE releasing
                    // _txLock. If this ran after the lock was released, a concurrent
                    // SendFrame() could assert transmit direction and then have Open()
                    // deassert it mid-frame.
                    if (_rs485Mode != Rs485ControlMode.Auto)
                    {
                        try
                        {
                            if (_rs485Mode == Rs485ControlMode.Rts)
                                _port.RtsEnable = false;
                            else if (_rs485Mode == Rs485ControlMode.Dtr)
                                _port.DtrEnable = false;
                        }
                        catch { /* Ignore */ }
                    }

                    _closing = false;
                }
                catch
                {
                    _closing = true;
                    throw;
                }
            }
        }
    }

    /// <inheritdoc/>
    /// <summary>
    /// Sends a PCCC command frame to the slave and waits for the response.
    /// Implements the correct 5‑step half‑duplex master transaction with retry on NAK or timeout.
    /// </summary>
    public override void SendFrame(byte[] innerFrame)
    {
        if (innerFrame == null || innerFrame.Length == 0)
            throw new ArgumentException("Inner frame cannot be null or empty.", nameof(innerFrame));

        // Everything the transaction produces is captured here and emitted only
        // after _txLock is released. This keeps every callback (OnRawFrameSent AND
        // OnFrameReceived) out of the lock — a subscriber that blocks on a thread
        // calling SendFrame()/Close() would otherwise deadlock — and guarantees
        // the callbacks fire even when the transaction throws.
        List<byte[]>? sentRawFrames = null;
        byte[]? responseInnerFrame = null;
        byte[]? responseRaw = null;
        ExceptionDispatchInfo? pending = null;

        try
        {
            lock (_txLock)   // Only one transaction at a time
            {
                if (_closing || _disposing)
                    throw new InvalidOperationException("Transport is closing or disposed.");

                // Snapshot the slave address ONCE for the whole transaction. The
                // command DST and every subsequent poll must target the same node;
                // reading _slaveAddress separately at each step would let a
                // concurrent SlaveAddress update command one node and poll another.
                int slaveAddress = _slaveAddress;

                // On a half-duplex multidrop link the slave polls on its node
                // address and expects that same address as the command frame's DST
                // byte. Callers (e.g. the gateway) build the PDU with a generic
                // DST, so rewrite it to the snapshotted SlaveAddress here. Work on a
                // copy so the caller's buffer is left untouched.
                byte[] addressedFrame = (byte[])innerFrame.Clone();
                addressedFrame[0] = (byte)slaveAddress;

                // Build the complete wire frame (includes DLE STX/ETX, DLE stuffing, checksum)
                byte[] commandFrame = BuildWireFrame(addressedFrame);
                const int maxCmdRetries = 3;
                bool commandAcknowledged = false;

                // Step 1 & 2: Send command frame, retry on NAK or timeout up to 3 times (spec §6.3)
                //
                // Nothing in this block writes _currentState directly: every exit
                // path, normal or exceptional, runs the finally below, which
                // disarms under _stateLock. Bare writes here would be both
                // redundant and unsynchronised — the receive thread reads this
                // field while holding that lock.
                if (!TryBeginActiveOperation())
                    throw new InvalidOperationException("Transport is closing.");
                try
                {
                    for (int attempt = 0; attempt < maxCmdRetries; attempt++)
                    {
                        // Reset flags and event atomically under _stateLock to avoid
                        // losing a signal that arrives between the flag reset and event reset.
                        lock (_stateLock)
                        {
                            // Recheck under the lock BEFORE resetting the event.
                            // Close() sets _closing and signals _stateEvent without
                            // holding _txLock; if that lands between the check above
                            // and this reset, the reset wipes the wake-up and we sit
                            // out the full ACK timeout while Close() waits on _txLock.
                            if (_closing || _disposing)
                                throw new InvalidOperationException("Send aborted: transport is closing.");

                            ResetTransactionFlags();
                            _currentState = MasterState.WaitingForCommandAck;
                            _stateEvent.Reset();
                        }
                        // Send the frame (event is deferred until after transaction)
                        SendDataFrame(commandFrame);
                        sentRawFrames ??= new List<byte[]>();
                        sentRawFrames.Add(commandFrame);

                        if (WaitForCommandAck(out bool wasNak))
                        {
                            commandAcknowledged = true;
                            // Reset backoff after successful ACK to prevent latency creep.
                            SleepDelay = 0;
                            break;
                        }

                        // Shutdown requested: stop retrying and surface as a send failure rather
                        // than exhausting all attempts and their backoff delays.
                        if (_closing || _disposing)
                            throw new InvalidOperationException("Send aborted: transport is closing.");

                        // If this was the last attempt, throw timeout exception
                        if (attempt == maxCmdRetries - 1)
                            throw new TimeoutException(
                                $"Slave did not respond to command frame after {maxCmdRetries} attempts.");

                        // Backoff: increase delay if NAK, otherwise use current SleepDelay
                        if (wasNak && SleepDelay < 400)
                            SleepDelay += 50;
                        if (WaitForShutdownOrDelay(SleepDelay > 0 ? SleepDelay : 20))
                            throw new InvalidOperationException("Send aborted: transport is closing.");
                    }
                }
                finally
                {
                    // If SendDataFrame threw after the state was armed, the arm
                    // must not outlive the attempt: a later ACK would otherwise be
                    // claimed for a transaction that has already failed, and its
                    // delivery suppressed.
                    lock (_stateLock)
                    {
                        _currentState = MasterState.Idle;
                    }
                    EndActiveOperation();
                }

                if (!commandAcknowledged)
                {
                    throw new TimeoutException(
                        $"Slave NAK'd command frame {maxCmdRetries} times. Communication failed.");
                }

                // Step 3 & 4: Poll for response. PollForResponse arms/disarms
                // _currentState per attempt (see there), so we do not pre-arm here.
                // PollForResponse disarms in its own finally, under _stateLock.
                responseInnerFrame = PollForResponse(sentRawFrames, slaveAddress, out responseRaw);

                // Step 5: Final ACK already sent inside PollForResponse.
                if (responseInnerFrame == null)
                    throw new TimeoutException("No response data received from slave after polling.");
            } // release _txLock
        }
        catch (Exception ex)
        {
            // Capture and rethrow after the safe zone so the frames already written
            // still raise their callbacks in protocol order.
            pending = ExceptionDispatchInfo.Capture(ex);
        }

        // --- Safe zone: raise all callbacks outside _txLock, in protocol order ---
        // Sent frames first (in the order they went on the wire), then the received
        // response. This prevents reentrancy deadlocks if a subscriber calls
        // SendFrame()/Close() from within a callback.
        //
        // These events are deliberately NOT protected by a generation-aware
        // callback lease, though a concurrent Close() can finish before they run.
        // A lease does not remove that race, it relocates it: teardown then blocks
        // for as long as a subscriber's handler takes, which for a gateway that
        // must be able to drop a misbehaving link is the worse failure. The lease
        // also needs reentrancy detection, and every bug of that family we have
        // hit came from exactly that mechanism. Misattribution of a late reply is
        // prevented one layer up instead: PcccGateway allocates gateway TNS values
        // monotonically and skips any still pending, so a stale reply can only ever
        // match the request that actually produced it.
        if (sentRawFrames != null)
        {
            foreach (byte[] frame in sentRawFrames)
                OnRawFrameSent(frame);
        }

        if (responseInnerFrame != null)
        {
            // Raw-before-decoded: emit the response's raw frame here (not on the
            // receive thread) so it always precedes OnFrameReceived.
            if (responseRaw != null)
                OnRawFrameReceived(responseRaw);
            OnFrameReceived(responseInnerFrame);
        }

        pending?.Throw();
    }

    // --- Private transaction helpers ---
    private void ResetTransactionFlags()
    {
        _commandAckReceived = false;
        _commandNakReceived = false;
        _pollNakReceived = false;
        _responseDataReceived = false;
        _responseDataFrame = null;
        _responseRawFrame = null;
    }

    private bool TryBeginActiveOperation()
    {
        lock (_stateLock)
        {
            if (_closing || _disposing)
                return false;
            _activeOperations++;
            return true;
        }
    }

    private bool WaitForShutdownOrDelay(int milliseconds)
    {
        if (milliseconds <= 0)
            milliseconds = 20;
        return _shutdownEvent.Wait(milliseconds) || _closing || _disposing;
    }

    private void EndActiveOperation()
    {
        lock (_stateLock)
        {
            if (--_activeOperations == 0)
                Monitor.PulseAll(_stateLock);
        }
    }

    /// <summary>
    /// Waits for the slave to respond with ACK or NAK after sending a command frame.
    /// Uses ManualResetEventSlim to avoid tight polling and reduce CPU usage.
    /// </summary>
    private bool WaitForCommandAck(out bool wasNak)
    {
        // Wait for the event to be set by the receive thread, or timeout.
        _stateEvent.Wait(CommandAckTimeoutMs);

        // Disarm and snapshot in ONE critical section, then decide on the
        // snapshot rather than on the Wait() result. The receive thread can
        // claim an ACK after Wait() has already returned false but before we
        // take the lock; trusting Wait() there would retransmit a command the
        // slave has already accepted — a duplicate write, not just a lost reply.
        bool ackReceived, nakReceived;
        lock (_stateLock)
        {
            _currentState = MasterState.Idle;
            ackReceived = _commandAckReceived;
            nakReceived = _commandNakReceived;
        }

        if (ackReceived) { wasNak = false; return true; }
        if (nakReceived) { wasNak = true; return false; }

        wasNak = false;
        return false;
    }

    /// <summary>
    /// Polls the slave for a response by sending DLE ENQ + SlaveAddress repeatedly.
    /// Uses ManualResetEventSlim to avoid tight polling and reduce CPU usage.
    /// </summary>
    /// <param name="sentFramesCollector">List to collect any additional frames sent (poll frames and final ACK).</param>
    /// <param name="slaveAddress">Slave node address snapshotted for the whole transaction.</param>
    /// <returns>The response inner frame, or null if no response received.</returns>
    private byte[]? PollForResponse(List<byte[]>? sentFramesCollector, int slaveAddress, out byte[]? responseRaw)
    {
        responseRaw = null;
        if (!TryBeginActiveOperation()) return null;
        try
        {
            for (int attempt = 0; attempt < MaxPollAttempts; attempt++)
            {
                if (_closing || _disposing) return null;

                // Reset flags/event AND arm poll ownership atomically, immediately
                // before sending the poll. Arming here (rather than once before the
                // loop) guarantees that after a timed-out attempt the next attempt
                // restores WaitingForPollResponse — otherwise a response claimed at
                // the timeout boundary would leave the state Idle and every later
                // response would be ignored until the transaction times out.
                lock (_stateLock)
                {
                    // Same reasoning as the command arm: a shutdown signal that
                    // arrives between the loop's _closing check and this reset must
                    // not be wiped, or we wait out the poll timeout for nothing.
                    if (_closing || _disposing)
                        return null;

                    _pollNakReceived = false;
                    _responseDataReceived = false;
                    _responseDataFrame = null;
                    _responseRawFrame = null;
                    _stateEvent.Reset();
                    _currentState = MasterState.WaitingForPollResponse;
                }
                // Send poll (collect frame for later callback)
                SendPoll(slaveAddress);
                byte[] pollFrame = new byte[] { DLE, ENQ, (byte)slaveAddress };
                sentFramesCollector?.Add(pollFrame);

                // Wait for either NAK or data frame using the event.
                _stateEvent.Wait(PollResponseTimeoutMs);

                // Disarm AND snapshot in one critical section, then decide on the
                // snapshot rather than on the Wait() result. A response claimed by
                // the receive thread after Wait() timed out but before this lock
                // would otherwise be discarded and then wiped by the next attempt's
                // reset — losing the reply and, worse, never sending the final ACK
                // the slave is waiting for.
                bool gotData, gotNak;
                byte[]? dataFrame, rawFrame;
                lock (_stateLock)
                {
                    _currentState = MasterState.Idle;
                    gotData   = _responseDataReceived;
                    dataFrame = _responseDataFrame;
                    rawFrame  = _responseRawFrame;
                    gotNak    = _pollNakReceived;
                }

                if (gotData && dataFrame != null)
                {
                    // Honoured even when the wait timed out: the frame is on the
                    // wire and the slave is owed its ACK. _txLock is still held and
                    // the active-operation count is non-zero, so Close() cannot have
                    // shut the port beneath us.
                    responseRaw = rawFrame;
                    // Step 5: Final ACK must go through direction control
                    byte[] ack = new byte[] { DLE, ACK };
                    SendWithDirectionControl(ack);
                    sentFramesCollector?.Add(ack);
                    return dataFrame;
                }

                if (_closing || _disposing) return null;

                if (gotNak)
                {
                    // Slave not ready – wait and continue polling
                    if (PollRetryDelayMs > 0 && WaitForShutdownOrDelay(PollRetryDelayMs))
                        return null;
                    continue;
                }

                // Timeout — keep polling; MaxPollAttempts governs how many times.
                continue;
            }
            return null;
        }
        finally
        {
            // Same reasoning as the command scope: a throw from SendPoll or from
            // the final ACK write must not leave poll ownership armed.
            lock (_stateLock)
            {
                _currentState = MasterState.Idle;
            }
            EndActiveOperation();
        }
    }

    // --- Transmission Methods (using direction control + echo suppression) ---
    private void SendPoll(int slaveAddress)
    {
        // Selective polling: DLE ENQ + SlaveAddress (3-byte, multi‑drop).
        // Uses the address snapshotted for the whole transaction.
        byte[] poll = new byte[] { DLE, ENQ, (byte)slaveAddress };
        SendWithDirectionControl(poll);
        // OnRawFrameSent is deferred to the caller (SendFrame)
    }

    private void SendDataFrame(byte[] frame)
    {
        SendWithDirectionControl(frame);
        // OnRawFrameSent is deferred to the caller (SendFrame)
    }

    /// <summary>
    /// Sends raw bytes with RS‑485 direction control.
    /// Also manages echo suppression if enabled.
    /// IMPORTANT: This method must only be called while holding _txLock.
    /// </summary>
    private void SendWithDirectionControl(byte[] data)
    {
        // Enable echo suppression BEFORE write (if configured).
        //
        // Overwrite rather than accumulate, deliberately. If the adapter turns out
        // to suppress echo in hardware, a residual count would keep growing and
        // start eating real response bytes; overwriting bounds the damage to one
        // frame, which the checksum then rejects.
        if (EchoSuppression)
        {
            lock (_echoLock)
            {
                _echoSuppressBytes = data.Length;
                _suppressEcho = true;
            }
        }

        if (_rs485Mode == Rs485ControlMode.Auto)
        {
            WritePort(data, 0, data.Length);
            // No direction control, echo suppression may still work if needed
            return;
        }

        try
        {
            if (_rs485Mode == Rs485ControlMode.Rts)
                _port.RtsEnable = true;
            else if (_rs485Mode == Rs485ControlMode.Dtr)
                _port.DtrEnable = true;

            if (_rtsAssertDelayMs > 0)
                Thread.Sleep(_rtsAssertDelayMs);

            WritePort(data, 0, data.Length);

            // Hold the line until the bytes have actually left the UART, then a
            // margin, before releasing it to the slave.
            //
            // WARNING — this is a heuristic, and it is the most likely field
            // failure in this class. ISerialPort.Write returns once the driver has
            // buffered the frame, NOT once the UART has shifted it out, so the
            // sleep below is the only thing standing between us and dropping RTS
            // mid-frame. It has never been exercised: every DF1 run so far has
            // gone over a virtual port, where RTS does nothing and there is no
            // line rate. Validate on the real adapter with a scope or an analyser
            // before trusting it, and raise RtsDeassertDelayMs if frames come back
            // truncated.
            //
            // bits per byte: start(1) + data(8) + parity(0 or 1) + stop(1)
            int bitsPerByte = 1 + 8 + (_port.Parity == Parity.None ? 0 : 1) + 1;
            int baud = _port.BaudRate > 0 ? _port.BaudRate : 9600;

            // Ceiling, not truncation: a frame needing 260.4 ms must not get 260.
            int transmitTimeMs = (data.Length * bitsPerByte * 1000 + baud - 1) / baud;
            int totalDelay = Math.Max(1, transmitTimeMs + _rtsDeassertDelayMs);
            Thread.Sleep(totalDelay);

            if (_rs485Mode == Rs485ControlMode.Rts)
                _port.RtsEnable = false;
            else if (_rs485Mode == Rs485ControlMode.Dtr)
                _port.DtrEnable = false;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("RS-485 direction control failed.", ex);
        }
    }

    // --- Receive Handler (State Machine + Echo Suppression) ---
    private void OnBytesReceived(object? sender, byte[] chunk)
    {
        // Accumulate all extracted frames so each one can be raised after
        // the active operation ends, preventing deadlock if a subscriber calls Close().
        List<byte[]>? rawFramesToRaise = null;

        if (!TryBeginActiveOperation()) return;

        try
        {
            // Apply echo suppression if enabled. Decide how much to drop in one
            // critical section, then do the copying outside it.
            byte[] filtered = chunk;
            if (EchoSuppression)
            {
                int discard = 0;
                lock (_echoLock)
                {
                    if (_suppressEcho && _echoSuppressBytes > 0)
                    {
                        discard = Math.Min(chunk.Length, _echoSuppressBytes);
                        _echoSuppressBytes -= discard;
                        if (_echoSuppressBytes <= 0)
                        {
                            _echoSuppressBytes = 0;
                            _suppressEcho = false;
                        }
                    }
                }

                if (discard >= chunk.Length)
                    return; // entire chunk was echo, ignore

                if (discard > 0)
                {
                    filtered = new byte[chunk.Length - discard];
                    Array.Copy(chunk, discard, filtered, 0, filtered.Length);
                }
            }

            lock (_rxLock)
            {
                // Check capacity BEFORE adding — see DF1FullDuplexTransport.OnBytesReceived
                // for why checking Count > MaxBufferBytes only after AddRange never actually
                // triggers: RingBuffer's capacity equals MaxBufferBytes exactly, so AddRange
                // itself throws InvalidOperationException the instant it would be exceeded.
                //
                // When only the COMBINED size exceeds capacity we drop the stale buffered
                // partial frame but keep the current chunk (it may be a complete valid
                // frame); only a chunk that is individually oversized is discarded outright,
                // matching the full-duplex recovery behaviour.
                if (filtered.Length + _rxBuffer.Count > MaxBufferBytes)
                {
                    _rxBuffer.Clear();
                    _frameStartTime = DateTime.MinValue;
                    if (filtered.Length > MaxBufferBytes)
                        return;
                }
                _rxBuffer.AddRange(filtered, 0, filtered.Length);

                bool consumed = true;
                while (consumed && _rxBuffer.Count >= 2)
                {
                    consumed = false;

                    // Synchronisation: find DLE
                    if (_rxBuffer[0] != DLE)
                    {
                        _rxBuffer.Advance(1);
                        consumed = true;
                        continue;
                    }

                    byte ctrl = _rxBuffer[1];

                    // --- ACK / NAK processing (with explicit state) ---
                    if (ctrl == ACK || ctrl == NAK)
                    {
                        _rxBuffer.Advance(2);
                        _frameStartTime = DateTime.MinValue;

                        lock (_stateLock)
                        {
                            if (_currentState == MasterState.WaitingForCommandAck)
                            {
                                if (ctrl == ACK)
                                    _commandAckReceived = true;
                                else if (ctrl == NAK)
                                    _commandNakReceived = true;
                                // Wake the waiting thread (WaitForCommandAck)
                                _stateEvent.Set();
                            }
                            else if (_currentState == MasterState.WaitingForPollResponse && ctrl == NAK)
                            {
                                _pollNakReceived = true;
                                // Wake the waiting thread (PollForResponse)
                                _stateEvent.Set();
                            }
                            // ACK during polling is ignored (should not happen)
                        }
                        consumed = true;
                        continue;
                    }

                    // --- Data frame: DLE STX ... DLE ETX ---
                    if (ctrl == STX)
                    {
                        if (_frameStartTime == DateTime.MinValue)
                            _frameStartTime = DateTime.UtcNow;

                        if ((DateTime.UtcNow - _frameStartTime).TotalMilliseconds > FrameTimeoutMs)
                        {
                            _rxBuffer.Advance(2);
                            _frameStartTime = DateTime.MinValue;
                            consumed = true;
                            continue;
                        }

                        // Find DLE ETX, skipping over stuffed DLE pairs
                        int etxIndex = -1;
                        for (int i = 2; i < _rxBuffer.Count - 1; i++)
                        {
                            if (_rxBuffer[i] == DLE)
                            {
                                if (_rxBuffer[i + 1] == DLE)
                                {
                                    i++; // skip the stuffed pair
                                    continue;
                                }
                                if (_rxBuffer[i + 1] == ETX)
                                {
                                    etxIndex = i;
                                    break;
                                }
                            }
                        }
                        if (etxIndex == -1)
                            break; // need more bytes

                        int csLen = (ChecksumType == CheckSumOptions.Crc) ? 2 : 1;
                        int totalLen = etxIndex + 2 + csLen;
                        if (_rxBuffer.Count < totalLen)
                            break; // checksum bytes not yet received

                        // Extract the complete frame using ArrayPool
                        byte[] rawFrame = System.Buffers.ArrayPool<byte>.Shared.Rent(totalLen);
                        try
                        {
                            Array.Clear(rawFrame, 0, totalLen);
                            _rxBuffer.Peek(rawFrame, 0, totalLen);

                            // Copy for event (cannot pass rented buffer out)
                            byte[] rawFrameCopy = new byte[totalLen];
                            Array.Copy(rawFrame, 0, rawFrameCopy, 0, totalLen);

                            _rxBuffer.Advance(totalLen);
                            _frameStartTime = DateTime.MinValue;

                            // Extract inner frame (unstuffed)
                            int payloadLen = etxIndex - 2;
                            byte[] stuffed = new byte[payloadLen];
                            Array.Copy(rawFrame, 2, stuffed, 0, payloadLen);
                            byte[] innerFrame = RemoveDleStuffing(stuffed);

                            // Validate checksum
                            bool valid;
                            if (ChecksumType == CheckSumOptions.Crc)
                            {
                                ushort calc = CalculateChecksum(innerFrame, CheckSumOptions.Crc);
                                ushort recv = (ushort)(rawFrame[etxIndex + 2] | (rawFrame[etxIndex + 3] << 8));
                                valid = calc == recv;
                            }
                            else
                            {
                                byte calc = (byte)CalculateChecksum(innerFrame, CheckSumOptions.Bcc);
                                byte recv = rawFrame[etxIndex + 2];
                                valid = calc == recv;
                            }

                            bool handedToSender = false;
                            if (valid)
                            {
                                lock (_stateLock)
                                {
                                    // Claim only the FIRST response, and leave the
                                    // WaitingForPollResponse state immediately. A second
                                    // valid frame (even from this same chunk) arriving
                                    // before SendFrame finishes the final ACK must not
                                    // overwrite _responseDataFrame/_responseRawFrame.
                                    if (_currentState == MasterState.WaitingForPollResponse
                                        && !_responseDataReceived)
                                    {
                                        _responseDataReceived = true;
                                        _responseDataFrame = innerFrame;
                                        // Hand the raw frame to SendFrame so it raises
                                        // OnRawFrameReceived right before OnFrameReceived.
                                        _responseRawFrame = rawFrameCopy;
                                        _currentState = MasterState.Idle;
                                        // Wake the waiting thread (PollForResponse)
                                        _stateEvent.Set();
                                        handedToSender = true;
                                    }
                                }
                                // Note: OnFrameReceived is normally raised from SendFrame
                                // for half-duplex, so we do not raise it here.
                            }

                            // Any frame NOT consumed as the poll response (invalid, or
                            // valid but arriving outside the poll wait) has its raw bytes
                            // raised here on the receive thread. The response frame's raw
                            // is deferred to SendFrame for correct ordering.
                            if (!handedToSender)
                                (rawFramesToRaise ??= new List<byte[]>()).Add(rawFrameCopy);
                            // Invalid frame – ignore for decoding (master will timeout)
                        }
                        finally
                        {
                            System.Buffers.ArrayPool<byte>.Shared.Return(rawFrame);
                        }
                        consumed = true;
                        continue;
                    }

                    // Unexpected byte after DLE – discard DLE
                    _rxBuffer.Advance(1);
                    consumed = true;
                }
            }
        }
        finally
        {
            // Release the active operation. After this, Close() can proceed without deadlock.
            EndActiveOperation();
        }

        // --- Safe zone: raise events outside the lock and active-operation scope ---
        // Subscribers may call Close() here without deadlock because _activeOperations is 0.
        // Posted, not invoked: this is the serial callback thread. FrameReceived
        // and the response's raw frame are NOT posted — SendFrame raises those on
        // the caller's own thread, where there is nothing to starve.
        if (rawFramesToRaise != null)
        {
            foreach (byte[] rawFrame in rawFramesToRaise)
            {
                PostRawFrameReceived(rawFrame);
            }
        }
    }

    /// <inheritdoc/>
    public override void Close()
    {
        lock (_lifecycleLock)
        {
            // First, signal shutdown independently of _txLock so that any SendFrame
            // currently waiting on _stateEvent or _shutdownEvent can wake up and
            // exit promptly. This prevents deadlock where SendFrame holds _txLock
            // while waiting, and Close() tries to acquire _txLock.
            lock (_stateLock)
            {
                if (_closing) return;
                _closing = true;
                _shutdownEvent.Set();
                try { _stateEvent.Set(); } catch { }

                // Shut the write gate here, not after _txLock is acquired: an
                // in-flight SendFrame holds that lock, and until the gate closes
                // it can still put a command or poll on the wire that its caller
                // will be told failed.
                CloseWireGate();
                // Active operations will be drained once they notice _closing.
                // We must not wait here with _stateLock held because SendFrame
                // may be inside a TryBeginActiveOperation/EndActiveOperation block
                // and need to exit before we can proceed.
            }

            // Now wait for any active operation to finish (they will exit promptly
            // because _closing is true and events are signaled). We take _txLock
            // only after we've marked closing and signaled, so SendFrame will
            // release _txLock quickly.
            lock (_txLock)
            {
                // Wait for active operations to finish after they've been woken.
                lock (_stateLock)
                {
                    while (_activeOperations > 0)
                        Monitor.Wait(_stateLock);
                }

                base.Close();
            }
        }
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        // Before any lock — see DF1FullDuplexTransport.Dispose for why.
        CompleteCallbacks();

        lock (_lifecycleLock)
        {
            // Idempotent: second call returns immediately.
            // Signal shutdown independently of _txLock to unblock any SendFrame.
            lock (_stateLock)
            {
                if (_disposing)
                    return;

                _disposing = true;
                _closing = true;
                _shutdownEvent.Set();
                try { _stateEvent.Set(); } catch { }

                // Shut the write gate here, not after _txLock is acquired: an
                // in-flight SendFrame holds that lock, and until the gate closes
                // it can still put a command or poll on the wire that its caller
                // will be told failed.
                CloseWireGate();
            }

            // Wait for active operations to finish and acquire _txLock to close port.
            lock (_txLock)
            {
                lock (_stateLock)
                {
                    while (_activeOperations > 0)
                        Monitor.Wait(_stateLock);
                }

                _port.BytesReceived -= OnBytesReceived;
                _stateEvent.Dispose();
                _shutdownEvent.Dispose();
                base.Dispose();
            }
        }
    }
}
