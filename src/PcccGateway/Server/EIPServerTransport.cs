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

using System.Net;
using System.Net.Sockets;
using System.Text;
using PcccGateway.Common;
using PcccGateway.Interface;

namespace PcccGateway.Server;

/// <summary>
/// EtherNet/IP (EIP/PCCC) transport implementation targeting SLC 500 and MicroLogix PLCs.
///
/// Architecture overview
/// ─────────────────────
/// EIPServer implements IServerTransport and acts as the TCP transport layer.
/// Each accepted TCP connection runs in its own EIPClient instance which owns
/// the per-connection state (session handle, Forward Open / connected-messaging
/// state, pending Sender Context echo, pending Request ID echo).
///
/// The PCCC command processing path is:
///   TCP RX → EIPClient.ProcessAsync()
///          → HandleCommand()
///          → HandleUnconnectedSend() or HandleConnectedSend()
///          → ExtractAndDispatchPCCC()
///          → IServerTransport.PduReceived event  (raises Gateway.OnEipPduReceived)
///          → Gateway forwards the PDU verbatim to the PLC-side transport,
///            and routes the PLC's reply back by TNS — it does not interpret
///            the PCCC payload
///          → IServerTransport.SendResponse()     (routes back to originating client)
///          → EIPClient.SendSerializedAsync()   (serialized per-client send queue)
///          → SendUnconnectedResponse() or SendConnectedResponse()
///          → TCP TX
///
/// RSLinx compatibility requirements addressed here
/// ─────────────────────────────────────────────────
///   1. Sender Context (bytes 12-19 of every EIP header) must be echoed verbatim
///      in every response. RSLinx uses it to match responses to outstanding requests.
///   2. List Identity and List Services responses use a two-field CPF layout
///      (item count + items only, no Interface Handle / Timeout prefix). All other
///      responses (Unconnected Send, Connected Send, Forward Open/Close) use the
///      full six-field CPF layout.
///   3. RegisterSession must validate Transport Version; return status 0x00000001
///      for unsupported versions.
///   4. A UDP listener on port 44818 answers broadcast ListIdentity so the gateway
///      appears in RSLinx "Browse Network" without a manual IP entry.
///   5. Response ordering per client is guaranteed by a per-client SemaphoreSlim
///      inside EIPClient.SendSerializedAsync(), preventing interleaved responses
///      when two requests arrive in rapid succession.
///
/// References
/// ──────────
///   - Wire layouts follow the ODVA specs below; interoperable with EIP/PCCC clients (RSLinx, pycomm3, libplctag)
///   - ODVA EtherNet/IP Specification Volume 1 (Common Industrial Protocol)
///   - ODVA EtherNet/IP Specification Volume 2 (Adaptation for EtherNet)
/// </summary>
public partial class EIPServerTransport : IServerTransport, IDisposable
{
    // ── EIP Encapsulation constants ──────────────────────────────────────────
    // These constants eliminate magic numbers throughout the EIP server code.
    private const int EIP_HEADER_LEN = 24;

    /// <summary>Encapsulation options field offset: reserved, must be zero.</summary>
    private const int EIP_OPTIONS_OFFSET = 20;
    private const int CPF_PREFIX_LEN = 8;      // Interface Handle(4) + Timeout(2) + ItemCount(2)
    private const int NULL_ADDR_ITEM_LEN = 4;   // type(2) + length(2)
    private const int UCD_ITEM_HEADER_LEN = 4;  // type(2) + length(2)
    private const int CIP_PAYLOAD_OFFSET = EIP_HEADER_LEN + CPF_PREFIX_LEN + NULL_ADDR_ITEM_LEN + UCD_ITEM_HEADER_LEN; // 40

    // ── External dependencies ────────────────────────────────────────────────

    private readonly int _port;
    private readonly System.Net.IPAddress _bindAddress;

    // ── TCP server ───────────────────────────────────────────────────────────

    private TcpListener? _listener;
    private Task?        _acceptLoopTask;

    // Thread-safe client registry: session handle → EIPClient.
    private readonly Dictionary<uint, EIPClient> _clients    = new();
    private readonly object                       _clientLock = new object();
    private const int MAX_CLIENTS = 32;

    // Session handle generator. Stored as int so Interlocked.Increment can be
    // used; cast to uint when assigned because EIP session handles are 32-bit
    // unsigned values ranging from 0x00000001 to 0xFFFFFFFF.
    private int _nextSessionHandleInt = 0;

    // ── UDP listener (RSLinx broadcast ListIdentity) ─────────────────────────

    private UdpClient? _udpListener;
    private Task?      _udpTask;
    // Fallback local address for ListIdentity, resolved once at startup.
    //
    // NOT the primary source: both ListIdentity paths now derive the address from
    // the request itself, because "the machine's IPv4 address" is not a
    // well-defined thing on a multi-homed host. Enumerating interfaces returns
    // whichever one happens to come first, and on Windows that is regularly a
    // Hyper-V, WSL, VPN or VirtualBox adapter — leaving RSLinx with an address it
    // discovered the gateway on but cannot connect to. This value is used only
    // when the per-request lookup fails.
    private IPAddress? _cachedLocalAddress;

    // ── Lifecycle ────────────────────────────────────────────────────────────

    // _isDisposing: 0 = running, 1 = shutting down.
    // Written with Interlocked.CompareExchange; read via IsDisposing property
    // which uses Volatile.Read for a clean atomic read.
    private int _isDisposing = 0;

    /// <summary>
    /// True once Stop() or Dispose() has been called.
    /// Used by EIPClient to abort in-flight operations during shutdown.
    /// </summary>
    public bool IsDisposing => Volatile.Read(ref _isDisposing) != 0;

    private volatile bool _isRunning;
    private CancellationTokenSource? _cts;

    // Counts in-flight requests to allow graceful drain on Stop().
    private int _activeRequests = 0;

    // ── Health monitoring ────────────────────────────────────────────────────

    private Timer? _healthTimer;
    private long   _framesProcessed = 0;
    private long   _lastFrameCount  = 0;

    // ── EIP Encapsulation command codes (CIP Vol 2, Appendix A) ─────────────

    // Commands valid both before and after session registration.
    private const ushort EIP_LIST_SERVICES      = 0x0004; // Discover available services
    private const ushort EIP_LIST_IDENTITY      = 0x0063; // Read device identity
    private const ushort EIP_LIST_INTERFACES    = 0x0064; // Read CIP interface objects (optional)
    private const ushort EIP_REGISTER_SESSION   = 0x0065; // Open an EIP session
    private const ushort EIP_UNREGISTER_SESSION = 0x0066; // Close an EIP session

    // Commands that require a registered session.
    private const ushort EIP_UNCONNECTED_SEND = 0x006F; // CIP Unconnected messaging
    private const ushort EIP_CONNECTED_SEND   = 0x0070; // CIP Connected (class 3) messaging

    // EIP encapsulation status codes (CIP Vol 2, §2-3.2).
    private const uint EIP_STATUS_OK                  = 0x00000000;
    private const uint EIP_STATUS_INVALID_CMD         = 0x00000001; // Unsupported command
    private const uint EIP_STATUS_UNSUPPORTED_VERSION = 0x00000069; // Transport version mismatch

    // Supported EIP transport version.
    private const ushort EIP_TRANSPORT_VERSION = 1;

    // ── CIP Common Services (CIP Vol 1, §3-5.2) ─────────────────────────────

    private const byte CIP_SERVICE_GET_ATTRIBUTES_ALL   = 0x01; // Read all instance attributes
    private const byte CIP_SERVICE_GET_ATTRIBUTE_SINGLE = 0x0E; // Read one attribute
    private const byte CIP_SERVICE_FORWARD_OPEN         = 0x54; // Open Class 3 connection
    private const byte CIP_SERVICE_FORWARD_OPEN_EX      = 0x5B; // Extended Forward Open (large frames)
    private const byte CIP_SERVICE_FORWARD_CLOSE        = 0x4E; // Close Class 3 connection
    private const byte CIP_SERVICE_EXECUTE_PCCC         = 0x4B; // Execute PCCC command (SLC/MLGX)
    private const byte CIP_SERVICE_UNCONNECTED_SEND     = 0x52; // CM Unconnected Send wrapper

    // ── Common Packet Format item type codes (CIP Vol 1, §3-5.5) ────────────

    private const ushort CPF_ITEM_NULL_ADDRESS      = 0x0000; // Null address — no additional addressing
    private const ushort CPF_ITEM_CONNECTED_ADDRESS = 0x00A1; // Connected address — carries connection ID
    private const ushort CPF_ITEM_CONNECTED_DATA    = 0x00B1; // Connected data payload
    private const ushort CPF_ITEM_UNCONNECTED_DATA  = 0x00B2; // Unconnected data payload

    // ── CIP General Status codes (CIP Vol 1, §3-5.3) ────────────────────────

    private const byte CIP_STATUS_OK       = 0x00; // Success
    private const byte CIP_STATUS_FRAGMENT = 0x06; // Fragmented reply (more data follows)
    private const byte CIP_STATUS_SVC_UNSUPPORTED = 0x08; // Service not supported on this object

    // ── Forward Open / connection parameters ────────────────────────────────

    // Requested Packet Interval: 1 second expressed in microseconds.
    // Returned in Forward Open response as the actual O→T and T→O API.
    private const uint RPI_US = 1_000_000;

    // ── Identity Object (CIP Vol 1, §5-4) ───────────────────────────────────
    //
    // We emulate a 1761‑NET‑ENI Series C/D gateway, the most common
    // DF1‑to‑EIP bridge from Rockwell Automation.
    // EDS reference (0001000C00630300.eds from Rockwell EDS library):
    //   Vendor ID     = 1     (Rockwell Automation / Allen‑Bradley)
    //   Device Type   = 12    (Communications Adapter)
    //   Product Code  = 99    (1761-NET-ENI)
    //   Major Rev     = 3     (Series C/D)
    //   Minor Rev     = 20    (2.7 firmware)
    //   Product Name  = "1761-NET-ENI"

    // Locked fields. Device Type 0x000E = Programmable Logic Controller (per the
    // real PLC-5 EDS), which makes RSLinx talk to us directly as a PLC instead of
    // trying to route through us as a bridge. Product Code, Revision, and Product
    // Name are discovered from the connected PLC's Get Diagnostic Status; the
    // values below are the non-ENI fallback used until discovery succeeds.
    private const ushort EIP_VENDOR_ID    = 1;         // Rockwell Automation
    private const uint   EIP_SERIAL_NUM   = 0x600DCAFE; // arbitrary unique serial

    private const ushort EIP_DEVICE_TYPE  = 0x000E;    // Programmable Logic Controller
    private const ushort EIP_PRODUCT_CODE = 20;        // SLC 5/05 — blind default before discovery
    private const byte   EIP_REV_MAJOR    = 3;          // (matches the emulator's proven default)
    private const byte   EIP_REV_MINOR    = 6;
    private const string EIP_PRODUCT_NAME = "SLC 5/05";

    /// <summary>
    /// Identity Object attributes (bytes 5-8 of the Identity Item in
    /// ListIdentity and GetAttributes responses). Built once at construction.
    /// </summary>
    internal volatile byte[] _identityData;   // volatile: swapped by reference from the
                                               // supervisor thread, read by request threads

    // ── Vendor identification embedded in Execute PCCC Request ID ────────────
    //
    // Client identifier embedded in the Execute PCCC Request ID section of
    // every CIP Execute PCCC request (service 0x4B).  We echo them back in
    // our response when the client does not supply its own Request ID bytes.
    private const ushort VENDOR_ID            = 0xF33D;     // "tres"
    private const uint   VENDOR_SERIAL_NUMBER = 0x21504345; // "!PCE" (ASCII)

    // ── IServerTransport ──────────────────────────────────────────────────────

    /// <summary>Product name string used in log messages.</summary>
    // Current product name, updated on identity discovery (starts at the fallback).
    private volatile string _productName = EIP_PRODUCT_NAME;
    internal string ProductName => _productName;

    public string Name => "EIP";

    /// <summary>
    /// Raised when a complete PCCC PDU has been extracted from an incoming
    /// EIP frame.  The event argument carries both the raw PDU bytes and the
    /// originating <see cref="EIPClient"/> as the client context so that
    /// <see cref="SendResponse"/> can route the reply to the correct client.
    /// </summary>
    public event EventHandler<(byte[] pdu, object ClientContext)>? PduReceived;

    // ── Construction ─────────────────────────────────────────────────────────

    public EIPServerTransport(int port = EIP_DEFAULT_PORT, System.Net.IPAddress? bindAddress = null)
    {
        _port         = port;
        _bindAddress  = bindAddress ?? System.Net.IPAddress.Any;
        _identityData = BuildIdentityData(EIP_DEVICE_TYPE, EIP_PRODUCT_CODE, EIP_REV_MAJOR, EIP_REV_MINOR, EIP_PRODUCT_NAME);
    }

    public const int EIP_DEFAULT_PORT = 44818;

    // ── IServerTransport: Start / Stop ────────────────────────────────────────

    public void Start()
    {
        if (_isRunning) return;

        _isRunning = true;
        _cts       = new CancellationTokenSource();

        // TCP listener — accepts RSLinx, pycomm3, libplctag sessions.
        _listener = new TcpListener(_bindAddress, _port);
        _listener.Start();
        _acceptLoopTask = Task.Run(AcceptClientsAsync, _cts.Token);

        // UDP listener — answers broadcast ListIdentity so the gateway is
        // visible in RSLinx "Browse Network" without a manual IP entry.
        try
        {
            _udpListener = new UdpClient(new IPEndPoint(_bindAddress, _port));
            _udpTask     = Task.Run(HandleUdpBroadcastAsync, _cts.Token);
        }
        catch (Exception ex)
        {
            // UDP bind failure (e.g. port already in use) is non-fatal.
            // RSLinx manual-connect still works via TCP.
            Logger.Warn(this, $"UDP listener not started (RSLinx auto-browse disabled): {ex.Message}");
            _udpListener = null;
        }
        finally
        {
            // The health monitor is activated when logging disabled
            SetHealthStatsEnabled(!Logger.Enabled);

            // Resolve the fallback address. The check has to happen BEFORE the
            // loopback substitution: the previous form tested the result of
            // `?? IPAddress.Loopback`, which can never be null, so the warning
            // never fired and the transport silently advertised 127.0.0.1 — an
            // address no remote client can reach.
            IPAddress? fallback = GetLocalUnicastIPv4Address();
            if (fallback == null)
            {
                Logger.Warn(this, "No routable IPv4 address found; ListIdentity will fall back to " +
                                  "loopback and remote clients will not be able to connect");
                fallback = IPAddress.Loopback;
            }
            _cachedLocalAddress = fallback;

            Logger.Info(this, $"EtherNet/IP transport started on TCP/UDP port {_port}");
        }
    }

    /// <summary>
    /// Stops the EIP transport handler asynchronously.
    /// Drains in-flight requests, disposes all client connections,
    /// stops the TCP listener and UDP listener, and waits for background
    /// tasks to complete before returning.
    /// </summary>
    public async Task StopAsync()
    {
        // Only one caller proceeds; subsequent calls are no-ops.
        if (Interlocked.CompareExchange(ref _isDisposing, 1, 0) != 0) return;

        _isRunning = false;
        _cts?.Cancel();

        // Step 2: Stop health monitoring timer
        SetHealthStatsEnabled(false);

        // Drain in-flight requests (max 3 s).
        const int maxWaitMs = 3000;
        const int stepMs    = 100;
        int elapsed = 0;
        int active;
        while ((active = Volatile.Read(ref _activeRequests)) > 0 && elapsed < maxWaitMs)
        {
            await Task.Delay(stepMs).ConfigureAwait(false);
            elapsed += stepMs;
        }
        if (active > 0)
            Logger.Info(this, $"Stop: {active} request(s) still active after {maxWaitMs} ms - forcing shutdown");

        // Dispose all client connections.
        lock (_clientLock)
        {
            foreach (var c in _clients.Values)
                try { c.Dispose(); } catch { }
            _clients.Clear();
        }

        // Stop accepting new connections.
        _listener?.Stop();
        _listener = null;

        _udpListener?.Close();
        _udpListener = null;

        // Wait for background tasks to complete (with timeout).
        var tasksToWait = new List<Task>();
        if (_acceptLoopTask != null && !_acceptLoopTask.IsCompleted)
            tasksToWait.Add(_acceptLoopTask);
        if (_udpTask != null && !_udpTask.IsCompleted)
            tasksToWait.Add(_udpTask);

        if (tasksToWait.Count > 0)
        {
            try
            {
                await Task.WhenAll(tasksToWait).WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                Logger.Warn(this, "Background tasks did not complete within timeout");
            }
            catch (OperationCanceledException)
            {
                // Expected during shutdown.
            }
        }

       Logger.Info(this, "EtherNet/IP transport stopped");
    }

    /// <summary>
    /// Synchronous Stop() for IServerTransport compatibility.
    /// Blocks until all in-flight requests are drained or the 3-second
    /// timeout expires.
    /// </summary>
    public void Stop() => StopAsync().GetAwaiter().GetResult();

    /// <summary>
    /// Releases all managed resources held by EIPServer.
    /// Calls StopAsync() if not already stopped, then disposes the health
    /// timer and any remaining network resources as a safety net.
    /// Safe to call multiple times.
    /// </summary>
    public void Dispose()
    {
        // StopAsync sets _isDisposing = 1 via CompareExchange, so a second
        // call to either Stop() or Dispose() is a harmless no-op.
        Stop();

        // Safety-net disposal for resources that Stop() may not have reached
        // (e.g. if Start() was never called).
        _healthTimer?.Dispose();
        _healthTimer = null;

        try { _udpListener?.Dispose(); } catch { }
        try { _listener?.Stop();       } catch { }

        GC.SuppressFinalize(this);
    }

    // ── IServerTransport: SendResponse ────────────────────────────────────────

    /// <summary>
    /// Routes a PCCC response PDU back to the client that raised
    /// <see cref="PduReceived"/>.  <paramref name="clientContext"/> must be
    /// the <see cref="EIPRequestContext"/> instance that was passed as the
    /// event argument; any other value is silently ignored.
    ///
    /// Response ordering per client is guaranteed by
    /// <see cref="EIPClient.SendSerializedAsync"/>, which serializes all
    /// outgoing sends through a per-client SemaphoreSlim.  This prevents
    /// interleaved or reordered responses when two requests from the same
    /// client are processed concurrently on the thread pool.
    /// </summary>
    public void SendResponse(byte[] pdu, object clientContext)
    {
        if (clientContext is not EIPRequestContext context) return;
        if (!context.Client.IsConnected) return;

        Logger.Info(this, $"SendResponse -> session {context.Client.SessionHandle:X8}, PDU length={pdu.Length}");

        // Use SendSerializedAsync to guarantee FIFO ordering of responses
        // within a single client session.  The discard (_=) is intentional:
        // exceptions are caught inside SendSerializedAsync and logged there.
        _ = context.Client.SendSerializedAsync(pdu, context);
    }

    // ── Health monitoring ────────────────────────────────────────────────────

    /// <summary>
    /// Enables or disables the health monitor for this transport instance.
    /// When enabled, the health monitor is activated for visibility.
    /// When disabled, the health monitor is disabled to reduce overhead.
    /// </summary>
    /// <param name="enabled">True to enable logging, false for maximum performance</param>
    public void SetHealthStatsEnabled(bool enabled)
    {
        if (enabled)
        {
            // Activate periodic health stats when verbose logging is off.
            _healthTimer ??= new Timer(_ => LogHealthStats(), null, 15_000, 15_000);
            Logger.Always(this, "Logging disabled - health monitor active");
        }
        else
        {
            _healthTimer?.Dispose();
            _healthTimer = null;
        }
    }

    internal void IncrementFramesProcessed() =>
        Interlocked.Increment(ref _framesProcessed);

    private void LogHealthStats()
    {
        if (IsDisposing) return;
        long cur   = Interlocked.Read(ref _framesProcessed);
        long delta = cur - _lastFrameCount;
        _lastFrameCount = cur;

        int clientCount;
        lock (_clientLock) clientCount = _clients.Count;

        Logger.Always(this,
            $"EIP Rate: {delta / 15,6}/s | Total: {cur,10:N0} | " +
            $"Clients: {clientCount,2} | " +
            $"Memory: {GC.GetTotalMemory(false) / 1024,6:N0} KB");

        if (delta == 0 && cur > 0)
            Logger.Always(this, "No frames in last 15 s - check client connection");
    }

    // ── Request lifecycle guard ──────────────────────────────────────────────

    // Returned by BeginRequest(); Dispose() decrements the counter so Stop()
    // knows when all in-flight operations have completed.
    private sealed class RequestHandle : IDisposable
    {
        private readonly EIPServerTransport _p;
        public RequestHandle(EIPServerTransport p) => _p = p;
        public void Dispose()               => Interlocked.Decrement(ref _p._activeRequests);
    }

    // Dummy disposable used when we are already shutting down.
    private sealed class NoOpDisposable : IDisposable
    {
        public static readonly NoOpDisposable Instance = new();
        public void Dispose() { }
    }

    internal IDisposable BeginRequest()
    {
        if (IsDisposing) return NoOpDisposable.Instance;
        Interlocked.Increment(ref _activeRequests);
        return new RequestHandle(this);
    }

    // ── TCP accept loop ──────────────────────────────────────────────────────

    private async Task AcceptClientsAsync()
    {
        int errorCount = 0;
        const int maxErrors = 10;

        while (_isRunning && _listener != null)
        {
            try
            {
                var tcp = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                errorCount = 0; // Reset on success
                if (_isRunning)
                {
                    // Wrap the client handler to catch any unhandled exceptions that may
                    // escape the ProcessAsync try/catch. This prevents a fire-and-forget
                    // task from bringing down the entire process.
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await HandleClientAsync(tcp).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            Logger.Warn(this, $"Unhandled exception in client handler: {ex.Message}");
                        }
                    }, _cts!.Token);
                }
                else
                {
                    tcp.Close();
                }
            }
            catch (ObjectDisposedException) { break; }
            catch (Exception ex)
            {
                errorCount++;
                if (_isRunning)
                    Logger.Warn(this, $"Accept error ({errorCount}/{maxErrors}): {ex.Message}");

                if (errorCount >= maxErrors)
                {
                    Logger.Warn(this, $"Too many accept errors, stopping listener");
                    break;
                }

                await Task.Delay(100).ConfigureAwait(false);
            }
        }
    }

    private async Task HandleClientAsync(TcpClient tcp)
    {
        uint handle = (uint)Interlocked.Increment(ref _nextSessionHandleInt);
        var  client = new EIPClient(this, tcp, handle);

        // Check the limit and register the client under one lock so a burst of
        // simultaneous connections cannot slip past MAX_CLIENTS via a
        // check-then-act race.
        lock (_clientLock)
        {
            if (_clients.Count >= MAX_CLIENTS)
            {
                Logger.Warn(this, $"Max clients reached ({MAX_CLIENTS}), rejecting connection");
                tcp.Close();
                return;
            }
            _clients[handle] = client;
        }

        Logger.Info(this, $"Client connected, session handle=0x{handle:X8}");

        try
        {
            await client.ProcessAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Logger.Warn(this, $"Client 0x{handle:X8} unhandled exception: {ex.Message}");
        }
        finally
        {
            lock (_clientLock)
                _clients.Remove(handle);
            client.Dispose();
            Logger.Info(this, $"Client disconnected, session handle=0x{handle:X8}");
        }
    }

    // ── UDP broadcast handler (RSLinx auto-browse) ───────────────────────────

    /// <summary>
    /// Listens for UDP broadcast <c>ListIdentity</c> (0x0063) packets on port
    /// 44818 and sends a unicast reply to the originating host.  This is what
    /// makes the gateway appear in the RSLinx "Browse Network" tree without
    /// requiring the operator to type the IP address manually.
    /// </summary>
    private async Task HandleUdpBroadcastAsync()
    {
        while (_isRunning && _udpListener != null)
        {
            try
            {
                var result = await _udpListener.ReceiveAsync().ConfigureAwait(false);
                var data   = result.Buffer;
                Logger.Hex(this, "RX <-client:", data, data.Length);

                // Minimum EIP header is 24 bytes.
                if (data.Length < 24) continue;

                ushort cmd = (ushort)(data[0] | (data[1] << 8));
                if (cmd != EIP_LIST_IDENTITY) continue;

                // Advertise the address that faces THIS sender, not whichever
                // interface happens to enumerate first.
                IPAddress? local = GetLocalAddressFacing(result.RemoteEndPoint.Address)
                                  ?? _cachedLocalAddress;
                if (local == null) continue;
                IPEndPoint localEndpoint = new IPEndPoint(local, _port);

                // Echo the Sender Context from the request (bytes 12-19).
                ulong senderCtx = BitConverter.ToUInt64(data, 12);

                byte[] reply = BuildListIdentityResponse(senderCtx, sessionHandle: 0, localEndpoint);
                Logger.Hex(this, "TX ->client:", reply, reply.Length);
                await _udpListener.SendAsync(reply, reply.Length, result.RemoteEndPoint)
                                  .ConfigureAwait(false);

                Logger.Info(this, $"UDP ListIdentity reply sent to {result.RemoteEndPoint}");
            }
            catch (ObjectDisposedException) { break; }
            catch (Exception ex)
            {
                if (_isRunning) Logger.Warn(this, $"UDP broadcast handler error: {ex.Message}");
            }
        }
    }

    // ── Response builder helpers (static, shared by TCP and UDP paths) ───────

    /// <summary>
    /// Writes a standard 24-byte EIP encapsulation header into
    /// <paramref name="w"/>.
    /// <para>
    /// The <c>Length</c> field (bytes 2-3) is written as zero here; the
    /// caller must fix it by calling <see cref="FixEipLength"/> once all
    /// payload bytes have been written.
    /// </para>
    /// </summary>
    private static void WriteEipHeader(BinaryWriter w, ushort command,
                                       uint sessionHandle, ulong senderContext = 0)
    {
        w.Write(command);
        w.Write((ushort)0);     // Length — placeholder, fixed by FixEipLength()
        w.Write(sessionHandle);
        w.Write(EIP_STATUS_OK);
        w.Write(senderContext); // Must echo the value received from the client
        w.Write((uint)0);       // Options — always zero
    }

    /// <summary>
    /// Writes a standard 24-byte EIP header whose Status field carries an
    /// error code.  Used when a request cannot be fulfilled.
    /// </summary>
    private static void WriteEipErrorHeader(BinaryWriter w, ushort command,
                                            uint sessionHandle, uint errorStatus,
                                            ulong senderContext = 0)
    {
        w.Write(command);
        w.Write((ushort)0);     // Length
        w.Write(sessionHandle);
        w.Write(errorStatus);   // Non-zero status indicates an error
        w.Write(senderContext);
        w.Write((uint)0);
    }

    /// <summary>
    /// Writes the six-field CPF (Common Packet Format) header used inside
    /// <c>SendRRData</c> / <c>SendUnitData</c> packets: Interface Handle,
    /// Timeout, and item count.
    /// <para>
    /// <b>Do not</b> use this for List commands (ListIdentity, ListServices,
    /// ListInterfaces); those use a two-field layout — see
    /// <see cref="WriteListCpfHeader"/>.
    /// </para>
    /// </summary>
    private static void WriteSendCpfHeader(BinaryWriter w, ushort itemCount)
    {
        w.Write((uint)0);       // Interface Handle — always 0 for CIP
        w.Write((ushort)0);     // Timeout — 0 means "no timeout"
        w.Write(itemCount);
    }

    /// <summary>
    /// Writes the two-field CPF layout used in List command responses
    /// (ListIdentity, ListServices, ListInterfaces).  These responses do NOT
    /// include Interface Handle or Timeout before the item count.
    /// </summary>
    private static void WriteListCpfHeader(BinaryWriter w, ushort itemCount)
    {
        w.Write(itemCount);
    }

    /// <summary>
    /// Writes a Null Address CPF item (type 0x0000, length 0).
    /// Required as the first CPF item in Unconnected Send responses to
    /// comply with EIP Vol 2, §2-6.
    /// </summary>
    private static void WriteNullAddressItem(BinaryWriter w)
    {
        w.Write(CPF_ITEM_NULL_ADDRESS);
        w.Write((ushort)0);
    }

    /// <summary>
    /// Seeks back to byte offset 2 and writes the actual payload length
    /// (total bytes written minus the 24-byte EIP header), then seeks
    /// back to the current end so the caller can continue writing or flush.
    /// </summary>
    private static void FixEipLength(MemoryStream ms, BinaryWriter w)
    {
        long end = ms.Position;
        ms.Seek(2, SeekOrigin.Begin);
        w.Write((ushort)(end - 24));
        ms.Seek(end, SeekOrigin.Begin);
    }

    /// <summary>
    /// Builds the Identity Object attribute bytes shared by
    /// <c>ListIdentity</c> and <c>GetAttributesAll</c> / <c>GetAttributeSingle</c>
    /// responses.  Constructed once at static initialisation to avoid
    /// repeated allocations.
    /// </summary>
    /// <summary>
    /// Replaces the advertised Identity with values discovered from the connected
    /// PLC. Only Vendor ID stays fixed; Device Type, Product Code, Revision, and
    /// Product Name all reflect the real processor (Device Type is 12 or 14
    /// depending on the model, per its EDS). Thread-safe: the identity byte array
    /// is swapped by reference (an atomic operation).
    /// </summary>
    public void SetProductIdentity(ushort deviceType, ushort productCode, byte revMajor, byte revMinor, string productName)
    {
        _identityData = BuildIdentityData(deviceType, productCode, revMajor, revMinor, productName);
        _productName  = productName;
        Logger.Info(this, $"Identity set from PLC: type={deviceType} code={productCode} rev={revMajor}.{revMinor} name=\"{productName}\"");
    }

    private static byte[] BuildIdentityData(ushort deviceType, ushort productCode,
                                            byte revMajor, byte revMinor, string productName)
    {
        using var ms = new MemoryStream();
        using var w  = new BinaryWriter(ms);

        w.Write(EIP_VENDOR_ID);    // Attribute 1: Vendor ID          (UINT)
        w.Write(deviceType);       // Attribute 2: Device Type         (UINT)
        w.Write(productCode);      // Attribute 3: Product Code        (UINT)
        w.Write(revMajor);         // Attribute 4: Revision — Major    (USINT)
        w.Write(revMinor);         // Attribute 4: Revision — Minor    (USINT)
        w.Write((ushort)0x0060);   // Attribute 5: Status              (WORD)  — Owned, no faults
        w.Write(EIP_SERIAL_NUM);   // Attribute 6: Serial Number       (UDINT)

        // Attribute 7: Product Name — SHORT_STRING (1-byte length prefix + chars).
        byte[] nameBytes = Encoding.ASCII.GetBytes(productName);
        w.Write((byte)nameBytes.Length);
        w.Write(nameBytes);
        if ((nameBytes.Length % 2) != 0) w.Write((byte)0); // Pad to even byte boundary

        w.Write((byte)0x03); // Attribute 8: State (USINT) — 0x03 = Operational
        w.Write((byte)0x00); // Pad byte

        return ms.ToArray();
    }

    // ── Static List Identity response builder (used by both TCP and UDP) ─────


    /// <summary>
    /// Builds a complete List Identity response packet.
    /// </summary>
    /// <param name="senderContext">Sender Context bytes from request — echoed verbatim.</param>
    /// <param name="sessionHandle">EIP session handle; use 0 for UDP replies.</param>
    /// <param name="localEndpoint">Local endpoint (IP and port) for Socket Address field.</param>
    internal byte[] BuildListIdentityResponse(ulong senderContext, uint sessionHandle, IPEndPoint localEndpoint)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        // ========================================================================
        // Part 1: Encapsulation Header (24 bytes)
        // ========================================================================
        WriteEipHeader(w, EIP_LIST_IDENTITY, sessionHandle, senderContext);

        // ========================================================================
        // Part 2: CPF Header
        // ========================================================================
        WriteListCpfHeader(w, 1);  // Item count = 1

        // ========================================================================
        // Part 3: Identity Item
        // ========================================================================
        w.Write((ushort)0x000C);   // Item Type = Identity Object
        long itemLenPos = ms.Position;
        w.Write((ushort)0);        // Item Length (placeholder)

        // ========================================================================
        // Part 3a: Encapsulation Transport Version (MUST be 0x0001)
        // ========================================================================
        w.Write((ushort)1);        // Transport version = 1

        // ========================================================================
        // Part 3b: Socket Address (16 bytes)
        // ========================================================================
        w.Write((ushort)0x0002);   // sin_family = AF_INET
        // Convert port to network byte order (big-endian) per EIP spec
        ushort portBE = (ushort)((localEndpoint.Port >> 8) | ((localEndpoint.Port & 0xFF) << 8));
        w.Write(portBE);          // sin_port = 44818
        byte[] ipBytes = localEndpoint.Address.GetAddressBytes();
        w.Write(ipBytes);          // sin_addr
        w.Write(new byte[8]);      // sin_zero padding

        // ========================================================================
        // Part 3c: Identity Object Attributes
        // ========================================================================
        w.Write(_identityData);    // Vendor ID, Device Type, Product Code, etc.

        // ========================================================================
        // Fix lengths
        // ========================================================================
        long itemEnd = ms.Position;
        ms.Seek(itemLenPos, SeekOrigin.Begin);
        w.Write((ushort)(itemEnd - (itemLenPos + 2)));
        ms.Seek(itemEnd, SeekOrigin.Begin);

        FixEipLength(ms, w);
        return ms.ToArray();
    }

    /// <summary>
    /// Returns the local IPv4 address the OS would use to reach
    /// <paramref name="remote"/>, or null if that cannot be determined.
    /// </summary>
    /// <remarks>
    /// Connect() on a UDP socket sends nothing — it only binds the socket to the
    /// route the kernel picks for that destination, after which LocalEndPoint
    /// holds the source address. That is the address the peer must be told to
    /// come back to, and it is correct on a multi-homed host where enumerating
    /// interfaces is not.
    ///
    /// Loopback is returned rather than rejected. This answers "which address did
    /// this sender reach us on", and for a sender on this machine that answer IS
    /// loopback — traffic arriving from 127.0.0.1 cannot have originated
    /// elsewhere. Substituting a LAN address there would hand a local client an
    /// address it never used. The non-loopback filter belongs to
    /// <see cref="GetLocalUnicastIPv4Address"/>, which answers the different
    /// question of how this machine presents itself to the outside.
    /// </remarks>
    private static IPAddress? GetLocalAddressFacing(IPAddress remote)
    {
        if (remote.AddressFamily != AddressFamily.InterNetwork)
            return null;

        try
        {
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            probe.Connect(remote, 9);   // discard port; no traffic is generated
            IPAddress? local = (probe.LocalEndPoint as IPEndPoint)?.Address;
            return local?.AddressFamily == AddressFamily.InterNetwork ? local : null;
        }
        catch
        {
            return null;   // no route, or the socket was refused; caller falls back
        }
    }

    /// <summary>
    /// Normalises a socket endpoint to a usable IPv4 address, unwrapping the
    /// IPv6-mapped form a dual-stack listener reports.
    /// </summary>
    /// <remarks>
    /// Loopback is preserved, not filtered out. The caller is asking which address
    /// a client actually reached us on, and for a client on this machine that is
    /// 127.0.0.1 — an address it can certainly route to, unlike the LAN address
    /// that would otherwise be substituted for it. Only the fallback discovery in
    /// <see cref="GetLocalUnicastIPv4Address"/> filters loopback, because it is
    /// answering a different question.
    /// </remarks>
    internal static IPAddress? ToIPv4(System.Net.EndPoint? endpoint)
    {
        if (endpoint is not IPEndPoint ip) return null;

        IPAddress addr = ip.Address;
        if (addr.IsIPv4MappedToIPv6) addr = addr.MapToIPv4();

        return addr.AddressFamily == AddressFamily.InterNetwork ? addr : null;
    }

    /// <summary>
    /// Gets the first non-loopback IPv4 unicast address of the local machine.
    /// Used only as a fallback — see <see cref="_cachedLocalAddress"/>.
    /// </summary>
    private IPAddress? GetLocalUnicastIPv4Address()
    {
        foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            // Skip interfaces that are not operational
            if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
                continue;

            // Skip loopback interfaces
            if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                continue;

            foreach (var ua in ni.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily == AddressFamily.InterNetwork &&
                    !IPAddress.IsLoopback(ua.Address))
                {
                    return ua.Address;
                }
            }
        }
        return null;
    }

    // ── Binary read helpers ──────────────────────────────────────────────────

    private static ushort ReadU16(byte[] b, ref int o)
    {
        ushort v = (ushort)(b[o] | (b[o + 1] << 8));
        o += 2;
        return v;
    }

    private static uint ReadU32(byte[] b, ref int o)
    {
        uint v = (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));
        o += 4;
        return v;
    }
}

/// <summary>
/// EtherNet/IP (EIP) server transport: the gateway's client-facing frontend.
/// Handles TCP connections, session management, and CIP messaging.
///
/// This file contains the EIPClient nested class which manages individual
/// client connections and the EIPRequestContext class which encapsulates
/// per-request state to prevent race conditions.
///
/// KEY DESIGN PRINCIPLE: Request Context Encapsulation
/// ----------------------------------------------------
/// All per-request state (Sender Context, Request ID) is stored in an
/// EIPRequestContext object that flows with the request through the
/// processing pipeline. This prevents race conditions where a subsequent
/// request overwrites state before the previous response is sent.
///
/// Without this design, when logging is disabled (high performance mode),
/// the increased processing speed causes request B to overwrite
/// _pendingSenderContext before response A is sent, resulting in context
/// mismatch and client timeout.
/// </summary>
public sealed partial class EIPServerTransport
{
    /// <summary>
    /// Encapsulates per-request state for EIP messaging.
    ///
    /// This object is created when a request is received and flows through
    /// the entire processing pipeline. It carries the Sender Context (which
    /// must be echoed in the response) and the Request ID (which must be
    /// echoed in the PCCC response).
    ///
    /// By storing per-request state in this context object rather than in
    /// instance fields of EIPClient, we eliminate race conditions that
    /// occur when multiple requests are processed concurrently or when
    /// a subsequent request arrives before the previous response is sent.
    /// </summary>
    private sealed class EIPRequestContext
    {
        /// <summary>
        /// The client connection that originated this request.
        /// </summary>
        public EIPClient Client { get; }

        /// <summary>
        /// The Sender Context (8 bytes) from the EIP encapsulation header.
        /// Must be echoed verbatim in the response. RSLinx uses these bytes
        /// to correlate responses to outstanding requests.
        /// </summary>
        public ulong SenderContext { get; }

        /// <summary>
        /// The EIP command code from the encapsulation header.
        /// Used to route the response to the correct handler.
        /// </summary>
        public ushort Command { get; }

        /// <summary>
        /// The Request ID bytes from the CIP Execute PCCC request.
        /// Contains requestIdSize (1 byte) + vendor_id (2) + vendor_serial (4).
        /// Must be echoed verbatim in the PCCC response.
        /// </summary>
        public byte[]? RequestId { get; set; }

        /// <summary>
        /// Creates a new request context for a received EIP packet.
        /// </summary>
        /// <param name="client">The client connection that received the packet</param>
        /// <param name="senderContext">Sender Context from EIP header (bytes 12-19)</param>
        /// <param name="command">EIP command code from header (bytes 0-1)</param>
        public EIPRequestContext(EIPClient client, ulong senderContext, ushort command)
        {
            Client        = client;
            SenderContext = senderContext;
            Command       = command;
        }

        /// <summary>
        /// Whether the connection was established at the time the request was received.
        /// Captured to prevent race conditions between receive and send time.
        /// </summary>
        public bool IsConnectedAtReceive { get; set; }

        /// <summary>
        /// The CIP connection associated with this request (for Connected Send).
        /// </summary>
        public CipConnection? Connection { get; set; }
    }

    /// <summary>
    /// Represents a single CIP connection established via Forward Open.
    /// Multiple connections can exist per TCP session.
    /// </summary>
    private sealed class CipConnection
    {
        /// <summary>
        /// T→O connection ID proposed by the client. Echoed in Connected Send responses.
        /// </summary>
        public uint OrigConnectionId { get; set; }

        /// <summary>
        /// Server-assigned connection ID. Used as key in the connections dictionary
        /// and sent to client as orig_to_targ_conn_id in Forward Open response.
        /// </summary>
        public uint AssignedId { get; set; }

        /// <summary>
        /// Originator vendor ID from the Forward Open request. Part of the triple
        /// that identifies a connection uniquely; see HandleForwardClose.
        /// </summary>
        public ushort OriginatorVendorId { get; set; }

        /// <summary>
        /// Originator serial number from the Forward Open request. Part of the
        /// triple that identifies a connection uniquely; see HandleForwardClose.
        /// </summary>
        public uint OriginatorSerial { get; set; }

        /// <summary>
        /// Connection serial number from the Forward Open request.
        /// Used to identify the connection in Forward Close.
        /// </summary>
        public ushort SerialNumber { get; set; }

        /// <summary>
        /// Sequence number for outgoing Connected Send responses.
        /// Increments per message per connection.
        /// </summary>
        public int SequenceNumber;

        /// <summary>
        /// Whether this connection is active.
        /// </summary>
        public bool IsActive { get; set; }
    }

    /// <summary>
    /// Represents one TCP client connection in the EIP transport.
    ///
    /// This class handles:
    ///   - Per-connection session state (session handle, registration status)
    ///   - Connected messaging state (Forward Open/Close, connection IDs)
    ///   - Packet parsing and dispatching
    ///   - Response building and sending (using EIPRequestContext for state)
    ///
    /// All packet I/O for this connection runs on the async continuation chain
    /// started by ProcessAsync(); there is no secondary background thread.
    ///
    /// THREAD SAFETY:
    ///   The receive loop (ProcessAsync) and the send path (SendSerializedAsync)
    ///   may run on different thread-pool threads simultaneously.
    ///   _sendLock (SemaphoreSlim) serializes all outgoing sends to guarantee
    ///   FIFO response ordering and prevent interleaved writes on the same socket.
    ///   _disposed is checked in both paths before accessing the socket.
    /// </summary>
    private sealed class EIPClient : IDisposable
    {
        // ── Back-reference to transport (access to shared state) ──────────────
        private readonly EIPServerTransport _transport;

        // ── TCP plumbing ─────────────────────────────────────────────────────
        private readonly TcpClient     _tcp;
        private readonly NetworkStream _stream;
        private          bool          _disposed;

        // ── Per-client send serialization ────────────────────────────────────
        // SemaphoreSlim(1,1) used as an async mutex to guarantee that responses
        // are written to the socket in the order they are queued.  Without this,
        // two concurrent Task.Run sends can interleave their bytes on the wire.
        private readonly SemaphoreSlim _sendLock = new SemaphoreSlim(1, 1);

        // ── Session state ────────────────────────────────────────────────────

        // Session handle assigned by the server at RegisterSession time.
        // This is an immutable value set at construction.
        private readonly uint _sessionHandle;

        // Rate-limits the unexpected-CIP-path notice to once per connection. A
        // client that consistently uses 16-bit logical segments is a WORKING
        // client, so warning per request would bury the one line the notice
        // exists to surface — 518 of them for a single successful read cycle at
        // the tag counts this gateway is exercised with.
        private int _unexpectedPathWarned;

        // True after a successful RegisterSession exchange; commands that
        // require a session (Unconnected/Connected Send) are rejected otherwise.
        private bool _isRegistered;

        // ── Connected messaging state (established by Forward Open) ──────────

        // Shared counter for assigning unique connection IDs. Static so that
        // IDs do not repeat even across different client sessions.
        private static int s_nextConnectionId = 0;

        // Dictionary of active CIP connections keyed by AssignedId (server-assigned ID).
        // Supports multiple concurrent connections per TCP session.
        private readonly Dictionary<uint, CipConnection> _connections = new();
        private readonly object _connLock = new object();

        // NOTE: Per-request state (Sender Context, Request ID) is NOT stored here.
        // Instead, it is encapsulated in EIPRequestContext and passed through
        // the processing pipeline. This eliminates race conditions that occur
        // when multiple requests are processed concurrently.

        // ── Properties ───────────────────────────────────────────────────────

        public uint SessionHandle => _sessionHandle;

        /// <summary>
        /// True while the underlying TCP socket is connected and this object
        /// has not been disposed. Used by <see cref="EIPServerTransport.SendResponse"/>
        /// to guard against sending to already-disconnected clients.
        /// </summary>
        public bool IsConnected => !_disposed && _tcp.Connected;

        /// <summary>
        /// Number of active CIP connections.
        /// </summary>
        private int ActiveConnectionCount
        {
            get
            {
                lock (_connLock)
                    return _connections.Count;
            }
        }

        /// <summary>
        /// Sends a raw EIP response packet to the client. The data buffer must
        /// already contain a properly formatted EIP encapsulation header (24 bytes).
        /// Callers must hold _sendLock before calling this method.
        /// </summary>
        private async Task SendRawResponse(byte[] data, int length)
        {
            Logger.Hex(this, "TX ->client:", data, length);
            await _stream.WriteAsync(data, 0, length).ConfigureAwait(false);
        }

        // ── Construction ─────────────────────────────────────────────────────

        /// <summary>
        /// Creates a new EIP client connection handler.
        /// </summary>
        /// <param name="transport">Parent EIPTransport instance</param>
        /// <param name="tcp">Accepted TCP client connection</param>
        /// <param name="sessionHandle">Unique session handle for this connection</param>
        public EIPClient(EIPServerTransport transport, TcpClient tcp, uint sessionHandle)
        {
            _transport     = transport;
            _tcp           = tcp;
            _stream        = tcp.GetStream();
            _sessionHandle = sessionHandle;
        }

        // ── Main receive loop ────────────────────────────────────────────────

        /// <summary>
        /// Reads and dispatches EIP packets until the TCP connection closes
        /// or the transport is stopped.
        ///
        /// IMPORTANT: For each received packet, an EIPRequestContext is created
        /// to hold per-request state. This context flows through all processing
        /// and is used to build the response, preventing race conditions.
        /// </summary>
        public async Task ProcessAsync()
        {
            // Receive buffer: large enough for the maximum EIP packet size.
            // Sized for the maximum EIP packet (encapsulation header + CIP payload).
            var buf = new byte[65536];

            while (!_transport.IsDisposing)
            {
                try
                {
                    // Every EIP packet begins with a fixed 24-byte encapsulation header.
                    if (await ReadExactAsync(buf, 0, 24, idleFirstByte: true).ConfigureAwait(false) < 24)
                        break;

                    ushort command = (ushort)(buf[0] | (buf[1] << 8));
                    ushort length  = (ushort)(buf[2] | (buf[3] << 8));

                    // The Length field is peer-controlled and, at the protocol level, can be
                    // up to 65535 — enough that 24 (header) + length can exceed this fixed
                    // 65536-byte buffer. Reject that here, explicitly and before it is used to
                    // size a read, rather than letting Stream.ReadAsync's own bounds-check
                    // throw an ArgumentException that gets logged as a generic session error.
                    if (EIP_HEADER_LEN + length > buf.Length)
                    {
                        Logger.Warn(this, $"Rejected EIP request: length {length} exceeds receive buffer capacity - closing connection");
                        break;
                    }

                    // Session handle at offset 4 (uint, LE).
                    uint sessionHandle = BitConverter.ToUInt32(buf, 4);
                    // Status at offset 8 — checked per-command where needed.
                    // Sender Context at offset 12 (uint64, LE) — will be echoed in reply.
                    ulong senderContext = BitConverter.ToUInt64(buf, 12);

                    if ((command == EIP_UNREGISTER_SESSION || command == EIP_UNCONNECTED_SEND || command == EIP_CONNECTED_SEND) &&
                        (!_isRegistered || sessionHandle != _sessionHandle))
                    {
                        if (length > 0)
                        {
                            if (await ReadExactAsync(buf, EIP_HEADER_LEN, length, idleFirstByte: false).ConfigureAwait(false) < length)
                                break;
                        }

                        Logger.Info(this, $"Rejected EIP request for session handle 0x{sessionHandle:X8} - expected 0x{_sessionHandle:X8}");
                        continue;
                    }

                    // Create request context BEFORE reading payload. This context
                    // will carry all per-request state through the pipeline.
                    var context = new EIPRequestContext(this, senderContext, command);

                    if (length > 0)
                    {
                        if (await ReadExactAsync(buf, EIP_HEADER_LEN, length, idleFirstByte: false).ConfigureAwait(false) < length)
                            break;
                        Logger.Hex(this, "RX <-client:", buf, EIP_HEADER_LEN + length);
                    }

                    // Encapsulation options (bytes 20-23) are reserved and must be
                    // zero; the spec requires the receiver to discard a packet that
                    // sets them, since a non-zero value asks for behaviour we do not
                    // implement. Checked after the payload has been consumed so the
                    // stream stays framed, then the packet alone is dropped rather
                    // than the session.
                    uint encapOptions = BitConverter.ToUInt32(buf, EIP_OPTIONS_OFFSET);
                    if (encapOptions != 0)
                    {
                        Logger.Warn(this, $"Dropped EIP request with unsupported options 0x{encapOptions:X8}");
                        continue;
                    }

                    // Dispatch command with the request context.
                    await DispatchCommand(command, buf, length, context).ConfigureAwait(false);
                }
                catch (IOException) { break; }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Logger.Warn(this, $"ProcessAsync error (session 0x{_sessionHandle:X8}): {ex.Message}");
                    break;
                }
            }
        }

        // ── Low-level I/O helpers ────────────────────────────────────────────

        /// <summary>
        /// Reads exactly <paramref name="count"/> bytes into
        /// <paramref name="buf"/> starting at <paramref name="offset"/>.
        /// Returns the number of bytes read; a value less than
        /// <paramref name="count"/> indicates EOF or connection closure.
        /// </summary>
        // A partially-sent request must complete within this window. Applies only
        // once bytes have started arriving mid-message — a fully idle but
        // connected client (e.g. RSLinx between polls) is left alone.
        private const int PARTIAL_REQUEST_TIMEOUT_MS = 10_000;

        /// <summary>
        /// Reads exactly <paramref name="count"/> bytes. When
        /// <paramref name="idleFirstByte"/> is true the initial read may wait
        /// indefinitely (a connected client legitimately idles between requests);
        /// but once any byte of a message has arrived, the remainder must complete
        /// within <see cref="PARTIAL_REQUEST_TIMEOUT_MS"/>. This defeats a
        /// slow-loris client that sends a partial header/payload and then stalls,
        /// which would otherwise pin an EIPClient slot forever.
        /// <para>
        /// Note: NetworkStream.ReadTimeout is intentionally NOT used — it applies
        /// only to synchronous Read() and is ignored by ReadAsync(). The timeout
        /// must be enforced with a CancellationToken.
        /// </para>
        /// </summary>
        private async Task<int> ReadExactAsync(byte[] buf, int offset, int count, bool idleFirstByte)
        {
            int total = 0;
            CancellationTokenSource? cts = idleFirstByte ? null : new CancellationTokenSource(PARTIAL_REQUEST_TIMEOUT_MS);

            try
            {
                while (total < count)
                {
                    int n;
                    if (total == 0 && idleFirstByte)
                    {
                        n = await _stream.ReadAsync(buf, offset, 1).ConfigureAwait(false);
                        if (n == 0) break;
                        total += n;
                        if (total < count)
                            cts = new CancellationTokenSource(PARTIAL_REQUEST_TIMEOUT_MS);
                        continue;
                    }
                    else
                    {
                        try
                        {
                            n = await _stream.ReadAsync(buf, offset + total, count - total, cts!.Token)
                                            .ConfigureAwait(false);
                        }
                        catch (OperationCanceledException)
                        {
                            throw new IOException("Partial EIP request timed out - dropping connection.");
                        }
                    }
                    if (n == 0) break;
                    total += n;
                }
            }
            finally
            {
                cts?.Dispose();
            }
            return total;
        }


        // ── Command dispatch ─────────────────────────────────────────────────

        /// <summary>
        /// Dispatches an EIP command to the appropriate handler.
        /// <para>
        /// Per EIP spec (Vol 2, §2-3): List commands (ListIdentity, ListServices,
        /// ListInterfaces) and RegisterSession are valid without a registered
        /// session. All other commands require a prior RegisterSession.
        /// </para>
        /// </summary>
        /// <param name="command">EIP command code from header</param>
        /// <param name="buf">Raw packet buffer (includes header and payload)</param>
        /// <param name="length">Payload length (bytes after 24-byte header)</param>
        /// <param name="context">Request context containing per-request state</param>
        private async Task DispatchCommand(ushort command, byte[] buf, ushort length, EIPRequestContext context)
        {
            using var guard = _transport.BeginRequest();

            switch (command)
            {
                case EIP_REGISTER_SESSION:
                    await HandleRegisterSession(buf, length, context).ConfigureAwait(false);
                    break;

                case EIP_UNREGISTER_SESSION:
                    await HandleUnregisterSession(context).ConfigureAwait(false);
                    break;

                case EIP_LIST_SERVICES:
                    await HandleListServices(context).ConfigureAwait(false);
                    break;

                case EIP_LIST_IDENTITY:
                    await HandleListIdentity(context).ConfigureAwait(false);
                    break;

                case EIP_LIST_INTERFACES:
                    await HandleListInterfaces(context).ConfigureAwait(false);
                    break;

                case EIP_UNCONNECTED_SEND:
                    if (!_isRegistered) { Logger.Info(this, "Unconnected Send rejected - no session"); return; }
                    await HandleUnconnectedSend(buf, length, context).ConfigureAwait(false);
                    break;

                case EIP_CONNECTED_SEND:
                    if (!_isRegistered) { Logger.Info(this, "Connected Send rejected - no session"); return; }
                    await HandleConnectedSend(buf, length, context).ConfigureAwait(false);
                    break;

                default:
                    Logger.Info(this, $"Unknown command 0x{command:X4} - sending error reply");
                    await SendErrorReply(command, EIP_STATUS_INVALID_CMD, context).ConfigureAwait(false);
                    break;
            }
        }

        // ── Session management ───────────────────────────────────────────────

        /// <summary>
        /// Handles RegisterSession (0x0065).
        /// Validates the requested transport version and assigns a session handle.
        /// Responds with error status 0x0069 if the version is not supported.
        /// </summary>
        /// <param name="buf">Raw packet buffer with payload</param>
        /// <param name="context">Request context (contains Sender Context for echo)</param>
        private async Task HandleRegisterSession(byte[] buf, ushort length, EIPRequestContext context)
        {
            // The RegisterSession data payload is 4 bytes:
            //   bytes 24-25: Transport Version (UINT, LE)
            //   bytes 26-27: Options          (UINT, LE) — must be 0
            // Guard the payload length: a malformed RegisterSession with a short
            // (or zero) payload would otherwise read stale bytes left in the
            // reused receive buffer and validate the version against garbage.
            if (length < 4)
            {
                Logger.Info(this, $"RegisterSession: payload too short ({length} bytes) - rejected");
                await SendErrorReply(EIP_REGISTER_SESSION, EIP_STATUS_INVALID_CMD, context).ConfigureAwait(false);
                return;
            }
            ushort requestedVersion = (ushort)(buf[EIP_HEADER_LEN] | (buf[EIP_HEADER_LEN + 1] << 8));

            if (requestedVersion != EIP_TRANSPORT_VERSION)
            {
                Logger.Info(this, $"RegisterSession: unsupported transport version {requestedVersion} (expected {EIP_TRANSPORT_VERSION})");
                await SendErrorReply(EIP_REGISTER_SESSION, EIP_STATUS_UNSUPPORTED_VERSION, context)
                    .ConfigureAwait(false);
                return;
            }

            var response = new byte[28];

            // EIP header (24 bytes)
            response[0] = (byte)(EIP_REGISTER_SESSION & 0xFF);
            response[1] = (byte)((EIP_REGISTER_SESSION >> 8) & 0xFF);
            response[2] = 0x04; response[3] = 0x00;    // Data length = 4
            response[4] = (byte)(_sessionHandle & 0xFF);
            response[5] = (byte)((_sessionHandle >> 8)  & 0xFF);
            response[6] = (byte)((_sessionHandle >> 16) & 0xFF);
            response[7] = (byte)((_sessionHandle >> 24) & 0xFF);
            // Bytes 8-11:  Status = 0x00000000 (OK)
            // Bytes 12-19: Sender Context — echo from request context
            BitConverter.TryWriteBytes(response.AsSpan(12), context.SenderContext);
            // Bytes 20-23: Options = 0

            // Payload (4 bytes)
            response[24] = 0x01; response[25] = 0x00;  // Transport Version = 1
            response[26] = 0x00; response[27] = 0x00;  // Options = 0

            await SendRawResponse(response, response.Length).ConfigureAwait(false);
            _isRegistered = true;

            Logger.Info(this, $"RegisterSession: session 0x{_sessionHandle:X8} registered");
        }

        /// <summary>
        /// Handles UnregisterSession (0x0066).
        /// Releases the session and clears registration state.
        /// </summary>
        /// <param name="context">Request context (contains Sender Context for echo)</param>
        private async Task HandleUnregisterSession(EIPRequestContext context)
        {
            var response = new byte[24];

            response[0] = (byte)(EIP_UNREGISTER_SESSION & 0xFF);
            response[1] = (byte)((EIP_UNREGISTER_SESSION >> 8) & 0xFF);
            // Length = 0 (no payload for Unregister)
            response[4] = (byte)(_sessionHandle & 0xFF);
            response[5] = (byte)((_sessionHandle >> 8)  & 0xFF);
            response[6] = (byte)((_sessionHandle >> 16) & 0xFF);
            response[7] = (byte)((_sessionHandle >> 24) & 0xFF);
            BitConverter.TryWriteBytes(response.AsSpan(12), context.SenderContext);

            await SendRawResponse(response, response.Length).ConfigureAwait(false);
            _isRegistered = false;

            Logger.Info(this, $"UnregisterSession: session 0x{_sessionHandle:X8} released");
        }

        // ── List commands ────────────────────────────────────────────────────

        /// <summary>
        /// Responds to ListServices (0x0004).
        /// Returns one Target Item describing the "Communications" service.
        /// Format per EIP Vol 2, §2-4.2:
        ///   Item type   = 0x0100
        ///   Item length = 20 bytes (Version 2 + Capability 2 + Name 16)
        ///   Version     = 1
        ///   Capability  = 0x0020 (supports EIP encapsulation)
        ///   Name        = "Communications" (16 bytes, null-padded)
        /// </summary>
        /// <param name="context">Request context (contains Sender Context for echo)</param>
        private async Task HandleListServices(EIPRequestContext context)
        {
            using var ms = new MemoryStream();
            using var w  = new BinaryWriter(ms);

            WriteEipHeader(w, EIP_LIST_SERVICES, _sessionHandle, context.SenderContext);
            WriteListCpfHeader(w, 1); // Item count = 1

            w.Write((ushort)0x0100); // Target Item type: Communications
            w.Write((ushort)20);     // Item length: 2 + 2 + 16 = 20 bytes
            w.Write((ushort)1);      // Version = 1
            w.Write((ushort)0x0020); // Capability: supports EIP encapsulation

            var name = new byte[16];
            Encoding.ASCII.GetBytes("Communications").CopyTo(name, 0);
            w.Write(name);           // 16-byte null-padded name field

            FixEipLength(ms, w);
            await FlushAsync(ms).ConfigureAwait(false);
            Logger.Info(this, "ListServices response sent");
        }

        /// <summary>
        /// Responds to ListIdentity (0x0063) over TCP.
        /// Uses <see cref="BuildListIdentityResponse"/> which is also called
        /// by the UDP broadcast handler.
        /// </summary>
        /// <param name="context">Request context (contains Sender Context for echo)</param>
        private async Task HandleListIdentity(EIPRequestContext context)
        {
            // No guessing needed here: this connection's own local endpoint IS the
            // address this client reached us on, and therefore the one to advertise.
            IPAddress? local = ToIPv4(_tcp.Client.LocalEndPoint) ?? _transport._cachedLocalAddress;
            if (local == null)
            {
                Logger.Warn(this, "HandleListIdentity: no usable IPv4 address to advertise");
                return;
            }

            IPEndPoint localEndpoint = new IPEndPoint(local, _transport._port);
            byte[] reply = _transport.BuildListIdentityResponse(context.SenderContext, _sessionHandle, localEndpoint);
            await SendRawResponse(reply, reply.Length).ConfigureAwait(false);
            Logger.Info(this, $"ListIdentity response sent");
        }

        /// <summary>
        /// Responds to ListInterfaces (0x0068) with an empty list.
        /// The EIP specification defines this command but does not require
        /// devices to support any interface objects.
        /// </summary>
        /// <param name="context">Request context (contains Sender Context for echo)</param>
        private async Task HandleListInterfaces(EIPRequestContext context)
        {
            var response = new byte[26]; // 24-byte header + 2-byte item count

            response[0] = (byte)(EIP_LIST_INTERFACES & 0xFF);
            response[1] = (byte)((EIP_LIST_INTERFACES >> 8) & 0xFF);
            response[2] = 0x02; response[3] = 0x00;    // Length = 2
            response[4] = (byte)(_sessionHandle & 0xFF);
            response[5] = (byte)((_sessionHandle >> 8)  & 0xFF);
            response[6] = (byte)((_sessionHandle >> 16) & 0xFF);
            response[7] = (byte)((_sessionHandle >> 24) & 0xFF);
            BitConverter.TryWriteBytes(response.AsSpan(12), context.SenderContext);
            // Bytes 24-25: item count = 0

            await SendRawResponse(response, response.Length).ConfigureAwait(false);
            Logger.Info(this, "ListInterfaces response sent (empty)");
        }

        // ── Unconnected Send (0x006F) ────────────────────────────────────────

        /// <summary>
        /// Processes an Unconnected Send packet. The CPF payload may contain:
        ///   - A Null Address Item (type 0x0000) followed by a data item, or
        ///   - Just the data item (older clients).
        /// The data item payload is dispatched by service code:
        ///   0x01 / 0x0E → Get Attributes (Identity Object)
        ///   0x54 / 0x5B → Forward Open (standard / extended)
        ///   0x4E        → Forward Close
        ///   0x52        → CM Unconnected Send wrapper (PCCC inside)
        ///   0x4B        → Execute PCCC (direct, without wrapper)
        /// </summary>
        /// <param name="buf">Raw packet buffer</param>
        /// <param name="length">Payload length</param>
        /// <param name="context">Request context (carries per-request state)</param>
        private async Task HandleUnconnectedSend(byte[] buf, ushort length, EIPRequestContext context)
        {
            context.IsConnectedAtReceive = false;

            // Body starts immediately after the 24-byte EIP header.
            int packetEnd = EIP_HEADER_LEN + length;
            int offset = EIP_HEADER_LEN;

            // Interface Handle (4 bytes, always 0 for CIP) + Timeout (2 bytes).
            offset += 6;

            if (offset + 2 > packetEnd) return;
            ushort itemCount = (ushort)(buf[offset] | (buf[offset + 1] << 8));
            offset += 2;

            for (int i = 0; i < itemCount; i++)
            {
                if (offset + 4 > packetEnd) return;
                ushort itemType   = (ushort)(buf[offset]     | (buf[offset + 1] << 8));
                ushort itemLength = (ushort)(buf[offset + 2] | (buf[offset + 3] << 8));
                offset += 4;

                int itemStart = offset;

                if (itemType == CPF_ITEM_NULL_ADDRESS)
                {
                    // Null Address Item carries no data; skip it and continue.
                    if (itemStart + itemLength > packetEnd) return;
                    offset = itemStart + itemLength;
                    continue;
                }

                if (itemType == CPF_ITEM_UNCONNECTED_DATA && itemLength > 0)
                {
                    if (itemStart + itemLength > packetEnd)
                    {
                        Logger.Warn(this, "Unconnected Send: declared item length exceeds packet boundary - dropping");
                        return;
                    }

                    byte svc = buf[offset];

                    if (svc == CIP_SERVICE_GET_ATTRIBUTES_ALL ||
                        svc == CIP_SERVICE_GET_ATTRIBUTE_SINGLE)
                    {
                        await HandleGetAttributes(buf, offset, svc, context).ConfigureAwait(false);
                    }
                    else if (svc == CIP_SERVICE_FORWARD_OPEN ||
                            svc == CIP_SERVICE_FORWARD_OPEN_EX)
                    {
                        await HandleForwardOpen(buf, offset, itemLength,
                            isExtended: svc == CIP_SERVICE_FORWARD_OPEN_EX, context)
                            .ConfigureAwait(false);
                    }
                    else if (svc == CIP_SERVICE_FORWARD_CLOSE)
                    {
                        await HandleForwardClose(buf, offset, itemLength, context).ConfigureAwait(false);
                    }
                    else if (svc == CIP_SERVICE_UNCONNECTED_SEND)
                    {
                        // CM Unconnected Send wrapper (service 0x52).
                        // Structure (per ODVA CIP Vol 1, §3-5.8):
                        //   serviceCode(1) + pathSize(1) + path(pathSize*2)
                        //   + secsPerTick(1) + timeoutTicks(1)
                        //   + ucCmdLength(2) + [pad if ucCmdLength is odd]
                        //   + embedded PCCC request
                        int inner = offset + 1;                        // skip service code
                        if (inner >= packetEnd) return;
                        byte pathSize = buf[inner++];
                        if (inner + pathSize * 2 > packetEnd) return;
                        inner += pathSize * 2;                         // skip CM object path
                        inner += 2;                                    // secsPerTick + timeoutTicks
                        if (inner + 2 > packetEnd) return;
                        ushort ucLen = (ushort)(buf[inner] | (buf[inner + 1] << 8));
                        inner += 2;
                        // Pad byte required when embedded command length is odd.
                        if ((ucLen & 1) != 0)
                        {
                            if (inner >= packetEnd) return;
                            inner++;
                        }

                        // Validate that ucLen does not exceed the remaining packet.
                        if (inner + ucLen > packetEnd)
                        {
                            Logger.Warn(this, "CM Unconnected Send: ucLen exceeds buffer - dropping");
                            return;
                        }

                        ExtractAndDispatchPCCC(buf, inner, ucLen, context);
                    }
                    else
                    {
                        // Direct Execute PCCC (0x4B) — no CM wrapper.
                        ExtractAndDispatchPCCC(buf, itemStart, itemLength, context);
                    }
                    break; // Only one data item is expected per Unconnected Send.
                }

                offset = itemStart + itemLength; // skip unrecognised item
            }
        }

        // ── Connected Send (0x0070) ──────────────────────────────────────────

        /// <summary>
        /// Processes a Connected Send packet. The CPF payload must contain:
        ///   1. Connected Address Item (type 0x00A1, length 4) carrying the
        ///      connection ID that was issued in the Forward Open response.
        ///   2. Connected Data Item   (type 0x00B1) carrying a sequence
        ///      counter (2 bytes) followed by the CIP request payload.
        /// </summary>
        /// <param name="buf">Raw packet buffer</param>
        /// <param name="length">Payload length</param>
        /// <param name="context">Request context (carries per-request state)</param>
        private async Task HandleConnectedSend(byte[] buf, ushort length, EIPRequestContext context)
        {
            // Constants for EIP encapsulation and CPF prefix lengths.
            // Body starts immediately after the 24-byte EIP header.
            // Interface Handle (4 bytes, always 0 for CIP) + Timeout (2 bytes).
            int packetEnd = EIP_HEADER_LEN + length;
            int offset = EIP_HEADER_LEN + 6;
            if (packetEnd > buf.Length) return;

            if (offset + 2 > packetEnd) return;
            ushort itemCount = (ushort)(buf[offset] | (buf[offset + 1] << 8));
            offset += 2;

            for (int i = 0; i < itemCount && offset + 4 <= packetEnd; i++)
            {
                ushort itemType   = (ushort)(buf[offset]     | (buf[offset + 1] << 8));
                ushort itemLength = (ushort)(buf[offset + 2] | (buf[offset + 3] << 8));
                offset += 4;

                int itemStart = offset;

                if (itemType == CPF_ITEM_CONNECTED_ADDRESS && itemLength >= 4)
                {
                    if (itemStart + itemLength > packetEnd) return;

                    uint connId = (uint)(buf[offset]     | (buf[offset + 1] << 8) |
                                        (buf[offset + 2] << 16) | (buf[offset + 3] << 24));

                    CipConnection? conn;
                    lock (_connLock)
                        _connections.TryGetValue(connId, out conn);

                    if (conn == null)
                    {
                        Logger.Info(this, $"Connected Send: bad connection ID 0x{connId:X8} - packet dropped");
                        return;
                    }

                    // Store connection in context for response
                    context.Connection = conn;
                    context.IsConnectedAtReceive = true;
                    offset = itemStart + itemLength;
                }
                else if (itemType == CPF_ITEM_CONNECTED_DATA && itemLength >= 2)
                {
                    // Validate that the declared item length does not exceed the packet boundary.
                    if (itemStart + itemLength > packetEnd)
                    {
                        Logger.Warn(this, "Connected Send: itemLength exceeds buffer - dropping");
                        return;
                    }

                    // The Connected Address Item carries the connection ID and is
                    // where that ID is checked against the ones we issued. CPF puts it
                    // before the data item, and this loop follows arrival order — so a
                    // packet that sends the data item first would reach the dispatch
                    // below having skipped that check entirely, execute the PCCC command
                    // (writes included), and then have its reply built as unconnected
                    // because no connection was ever attached. Require the check to have
                    // happened.
                    if (context.Connection == null)
                    {
                        Logger.Warn(this, "Connected Send: data item arrived before a valid " +
                                          "Connected Address Item - dropping");
                        return;
                    }

                    // Read incoming sequence number (can be used for validation)
                    ushort incomingSeq = (ushort)(buf[offset] | (buf[offset + 1] << 8));
                    _ = incomingSeq;
                    ExtractAndDispatchPCCC(buf, offset + 2, (ushort)(itemLength - 2), context);
                    break;
                }
                else
                {
                    offset = itemStart + itemLength; // skip unknown item
                }
            }

            await Task.CompletedTask; // keep signature async for future async operations
        }

        // ── Forward Open / Close ─────────────────────────────────────────────

        /// <summary>
        /// Handles both standard Forward Open (0x54) and Extended Forward Open
        /// (0x5B). Parses the request to obtain the connection IDs proposed by
        /// the client, generates a unique server-side orig_to_targ_conn_id, and
        /// sends the appropriate Forward Open response.
        ///
        /// Connection ID semantics (per ODVA CIP Vol 1, Forward Open):
        ///   otConnId  — O→T connection ID proposed by the client
        ///   toConnId  — T→O connection ID proposed by the client
        ///   newId     — Fresh connection ID we assign for this connection.
        ///               Returned as orig_to_targ_conn_id in our response.
        /// </summary>
        /// <param name="buf">Raw packet buffer</param>
        /// <param name="offset">Starting offset of the CIP request</param>
        /// <param name="length">Total length of the CIP request</param>
        /// <param name="isExtended">True for Extended Forward Open (0x5B)</param>
        /// <param name="context">Request context (contains Sender Context for echo)</param>
        private async Task HandleForwardOpen(byte[] buf, int offset,
                                            ushort length, bool isExtended, EIPRequestContext context)
        {
            int requestEnd = offset + length;
            if (requestEnd > buf.Length) return;

            offset++;  // skip service code byte
            if (offset >= requestEnd) return;

            byte pathSize = buf[offset++];
            // Validate pathSize does not exceed request boundary.
            if (offset + pathSize * 2 > requestEnd)
            {
                Logger.Warn(this, "Forward Open: pathSize exceeds buffer - dropping");
                return;
            }
            offset += pathSize * 2;  // skip connection path

            // Both standard and extended Forward Open share these fields.
            const int commonFixedLength = 22;
            if (offset + commonFixedLength > requestEnd) return;
            _ = buf[offset++]; // secsPerTick  — not stored, we use RPI_US
            _ = buf[offset++]; // timeoutTicks — not stored
            uint   otConnId   = ReadU32(buf, ref offset); // O→T proposed ID
            uint   toConnId   = ReadU32(buf, ref offset); // T→O proposed ID
            ushort connSerial = ReadU16(buf, ref offset);
            ushort vendorId   = ReadU16(buf, ref offset);
            uint   serialNum  = ReadU32(buf, ref offset);
            offset++;        // timeoutMultiplier
            offset += 3;     // reserved bytes

            // Skip RPI and connection parameter fields (different widths per variant).
            if (isExtended)
            {
                const int extendedSuffixLength = 17;
                if (offset + extendedSuffixLength > requestEnd) return;
                offset += extendedSuffixLength; // otRpi(4) + otParamsEx(4) + toRpi(4) + toParamsEx(4) + transport(1)
            }
            else
            {
                const int standardSuffixLength = 13;
                if (offset + standardSuffixLength > requestEnd) return;
                offset += standardSuffixLength; // otRpi(4) + otParams(2) + toRpi(4) + toParams(2) + transport(1)
            }

            // Generate a unique connection ID for this session. The high bit
            // distinguishes server-generated IDs from client-generated ones.
            uint newId = ((uint)Interlocked.Increment(ref s_nextConnectionId) << 1) | 0x80000000;

            var conn = new CipConnection
            {
                OrigConnectionId = toConnId,
                AssignedId = newId,
                SerialNumber = connSerial,
                OriginatorVendorId = vendorId,
                OriginatorSerial = serialNum,
                SequenceNumber = 0,
                IsActive = true
            };

            // Add connection to dictionary only after ensuring we can send response,
            // or use try-finally to remove on failure.
            bool added = false;
            try
            {
                lock (_connLock)
                {
                    _connections[newId] = conn;
                    added = true;
                }

                Logger.Info(this, $"ForwardOpen{(isExtended ? "Ex" : "")}: " +
                    $"OT=0x{otConnId:X8} TO=0x{toConnId:X8} -> assigned TargID=0x{newId:X8}, " +
                    $"Active connections={_connections.Count}");

                await SendForwardOpenResponse(newId, toConnId, connSerial, vendorId, serialNum, isExtended, context)
                    .ConfigureAwait(false);
            }
            catch
            {
                // If response send fails, remove the connection to prevent leak.
                if (added)
                {
                    lock (_connLock)
                        _connections.Remove(newId);
                }
                throw;
            }
        }

        /// <summary>
        /// Handles Forward Close (0x4E) request.
        /// Closes the connected messaging session and resets connection state.
        /// </summary>
        private async Task HandleForwardClose(byte[] buf, int offset, ushort length, EIPRequestContext context)
        {
            // Bounded by the declared CIP item, not by the receive buffer. The
            // buffer is reused across packets, so checking only buf.Length let a
            // short or malformed Forward Close read its serial number and vendor
            // fields out of whatever the previous packet had left behind — and
            // those fields decide which connection gets closed. Forward Open has
            // always done it this way; this handler took `length` and ignored it.
            int requestEnd = offset + length;
            if (requestEnd > buf.Length) return;

            offset++;  // skip service code byte (0x4E)
            if (offset >= requestEnd) return;

            byte pathSize = buf[offset++];
            if (offset + pathSize * 2 > requestEnd)
            {
                Logger.Warn(this, "Forward Close: pathSize exceeds buffer - dropping");
                return;
            }
            offset += pathSize * 2;

            if (offset + 10 > requestEnd) return;
            _ = buf[offset++]; // secsPerTick
            _ = buf[offset++]; // timeoutTicks
            ushort connSerial = ReadU16(buf, ref offset);
            ushort vendorId   = ReadU16(buf, ref offset);
            uint   serialNum  = ReadU32(buf, ref offset);

            // Match on the full originator triple, not the serial number alone.
            // CIP specifies connection serial + vendor ID + originator serial
            // together precisely because the serial is chosen by the originator and
            // is only unique within it; a client holding two connections that
            // happen to share a serial would otherwise close whichever this lookup
            // reached first.
            CipConnection? conn = null;
            lock (_connLock)
            {
                conn = _connections.Values.FirstOrDefault(c =>
                    c.SerialNumber       == connSerial &&
                    c.OriginatorVendorId == vendorId &&
                    c.OriginatorSerial   == serialNum);
                if (conn != null)
                    _connections.Remove(conn.AssignedId);
            }

            if (conn != null)
                Logger.Info(this, $"ForwardClose: connection 0x{conn.AssignedId:X8} closed, " +
                           $"remaining connections={_connections.Count}");
            else
                Logger.Info(this, $"ForwardClose: connection serial 0x{connSerial:X4} not found");

            await SendForwardCloseResponse(connSerial, vendorId, serialNum, context).ConfigureAwait(false);
        }

        // ── Get Attributes (Identity Object) ────────────────────────────────

        /// <summary>
        /// Handles Get Attributes All (0x01) and Get Attribute Single (0x0E)
        /// requests for the Identity Object.
        /// </summary>
        private async Task HandleGetAttributes(byte[] buf, int offset, byte serviceCode, EIPRequestContext context)
        {
            using var ms = new MemoryStream();
            using var w  = new BinaryWriter(ms);

            WriteEipHeader(w, EIP_UNCONNECTED_SEND, _sessionHandle, context.SenderContext);
            WriteSendCpfHeader(w, 2);
            WriteNullAddressItem(w);

            w.Write(CPF_ITEM_UNCONNECTED_DATA);
            long lenPos    = ms.Position; w.Write((ushort)0);
            long dataStart = ms.Position;

            bool isGetAll = serviceCode == CIP_SERVICE_GET_ATTRIBUTES_ALL;
            byte replySvc = (byte)((isGetAll ? 0x01 : 0x0E) | 0x80);
            w.Write(replySvc);
            w.Write((byte)0x00);       // Reserved

            if (isGetAll)
            {
                w.Write(CIP_STATUS_OK);
                w.Write((byte)0x00);   // Additional status size = 0
                w.Write(_transport._identityData);   // Identity attributes payload
            }
            else
            {
                // Get Attribute Single asks for ONE attribute. _identityData is a
                // single opaque GetAttributesAll payload, so there is nothing here to
                // select from; the previous code returned the whole blob under a
                // success status, telling the client "here is your attribute" and
                // handing it all of them. A client parsing that reply gets garbage and
                // no indication why. Say we do not implement the service instead —
                // if a client ever needs it, this status is what will show up.
                Logger.Info(this, $"Get Attribute Single (0x{serviceCode:X2}) is not implemented - " +
                                  "replying with CIP status 0x08");
                w.Write(CIP_STATUS_SVC_UNSUPPORTED);
                w.Write((byte)0x00);   // Additional status size = 0
            }

            long dataEnd = ms.Position;
            ms.Seek(lenPos, SeekOrigin.Begin);
            w.Write((ushort)(dataEnd - dataStart));
            ms.Seek(dataEnd, SeekOrigin.Begin);

            FixEipLength(ms, w);
            await FlushAsync(ms).ConfigureAwait(false);
        }

        // ── Forward Open / Close response builders ───────────────────────────

        private async Task SendForwardOpenResponse(uint assignedId, uint toConnId,
            ushort connSerial, ushort vendorId, uint serialNum, bool isExtended, EIPRequestContext context)
        {
            byte replySvc = isExtended ? (byte)0xDB : (byte)0xD4;

            using var ms = new MemoryStream();
            using var w  = new BinaryWriter(ms);

            WriteEipHeader(w, EIP_UNCONNECTED_SEND, _sessionHandle, context.SenderContext);
            WriteSendCpfHeader(w, 2);
            WriteNullAddressItem(w);

            w.Write(CPF_ITEM_UNCONNECTED_DATA);
            long lenPos    = ms.Position; w.Write((ushort)0);
            long dataStart = ms.Position;

            // Forward Open Response body — per ODVA CIP Vol 1, §3-5.5 (Forward Open reply).
            w.Write(replySvc);          // Reply service code (0xD4 or 0xDB)
            w.Write((byte)0x00);        // Reserved
            w.Write(CIP_STATUS_OK);     // General status
            w.Write((byte)0x00);        // Additional status size = 0
            w.Write(assignedId);        // orig_to_targ_conn_id — client uses this in Connected Send
            w.Write(toConnId);          // targ_to_orig_conn_id — echoed in our Connected Send replies
            w.Write(connSerial);        // Connection serial number (echoed)
            w.Write(vendorId);          // Originator vendor ID (echoed)
            w.Write(serialNum);         // Originator serial number (echoed)
            w.Write(RPI_US);            // O→T Actual Packet Interval (µs)
            w.Write(RPI_US);            // T→O Actual Packet Interval (µs)
            w.Write((byte)0x00);        // Application data size = 0
            w.Write((byte)0x00);        // Reserved

            long dataEnd = ms.Position;
            ms.Seek(lenPos, SeekOrigin.Begin);
            w.Write((ushort)(dataEnd - dataStart));
            ms.Seek(dataEnd, SeekOrigin.Begin);

            FixEipLength(ms, w);
            await FlushAsync(ms).ConfigureAwait(false);

            Logger.Info(this, $"ForwardOpen response: replySvc=0x{replySvc:X2}, AssignedID=0x{assignedId:X8}");
        }

        private async Task SendForwardCloseResponse(ushort connSerial, ushort vendorId, uint serialNum, EIPRequestContext context)
        {
            using var ms = new MemoryStream();
            using var w  = new BinaryWriter(ms);

            WriteEipHeader(w, EIP_UNCONNECTED_SEND, _sessionHandle, context.SenderContext);
            WriteSendCpfHeader(w, 2);
            WriteNullAddressItem(w);

            w.Write(CPF_ITEM_UNCONNECTED_DATA);
            long lenPos    = ms.Position; w.Write((ushort)0);
            long dataStart = ms.Position;

            // Forward Close Response body — per ODVA CIP Vol 1, §3-5.5 (Forward Close reply).
            w.Write((byte)0xCE);   // Reply service: 0x4E | 0x80
            w.Write((byte)0x00);   // Reserved
            w.Write(CIP_STATUS_OK);
            w.Write((byte)0x00);   // Additional status size = 0
            w.Write(connSerial);   // Connection serial number (echoed)
            w.Write(vendorId);     // Originator vendor ID (echoed)
            w.Write(serialNum);    // Originator serial number (echoed)
            w.Write((byte)0x00);   // Connection path size = 0
            w.Write((byte)0x00);   // Reserved

            long dataEnd = ms.Position;
            ms.Seek(lenPos, SeekOrigin.Begin);
            w.Write((ushort)(dataEnd - dataStart));
            ms.Seek(dataEnd, SeekOrigin.Begin);

            FixEipLength(ms, w);
            await FlushAsync(ms).ConfigureAwait(false);
        }

        // ── PCCC extraction and dispatch ─────────────────────────────────────

        /// <summary>
        /// Parses a CIP Execute PCCC request (service 0x4B) out of
        /// <paramref name="buf"/> starting at <paramref name="startOffset"/>,
        /// builds a PCCC-style PDU, saves the Request ID bytes into the context
        /// for response echoing, and raises <see cref="PduReceived"/>.
        /// <para>
        /// PDU layout handed to <c>Gateway.OnEipPduReceived</c>:
        ///   [DST, SRC, CMD, STS, TNS_LO, TNS_HI, FUNC?, DATA...]
        /// </para>
        /// <para>
        /// Request ID section layout (CIP Execute PCCC request, per ODVA/AB PCCC):
        ///   requestIdSize (1 byte) — total size of this section including itself
        ///   vendor_id     (2 bytes)
        ///   vendor_serial (4 bytes)
        ///   → requestIdSize is always 7 (1 + 2 + 4). Bytes to skip = requestIdSize − 1.
        /// </para>
        /// </summary>
        /// <param name="buf">Raw packet buffer</param>
        /// <param name="startOffset">Offset where the PCCC request begins</param>
        /// <param name="itemLength">Total length of the PCCC request</param>
        /// <param name="context">Request context (Request ID will be stored here)</param>
        private void ExtractAndDispatchPCCC(byte[] buf, int startOffset, ushort itemLength, EIPRequestContext context)
        {
            int offset  = startOffset;
            int itemEnd = startOffset + itemLength;

            if (offset >= buf.Length || offset >= itemEnd) return;

            // ── Service code ────────────────────────────────────────────────
            byte svc = buf[offset++];
            if (svc != CIP_SERVICE_EXECUTE_PCCC)
            {
                Logger.Info(this, $"ExtractAndDispatchPCCC: unexpected service 0x{svc:X2} (expected 0x4B)");
                return;
            }

            // ── CIP path ────────────────────────────────────────────────────
            if (offset >= itemEnd || offset >= buf.Length) return;
            byte pathSize = buf[offset++];
            int pathBytes = pathSize * 2;
            // Validate path size does not exceed bounds.
            if (offset + pathBytes > buf.Length || offset + pathBytes > itemEnd)
            {
                Logger.Warn(this, "ExtractAndDispatchPCCC: pathSize exceeds buffer - dropping");
                return;
            }

            // Execute PCCC should address the PCCC Object, class 0x67 instance 1,
            // which as an 8-bit logical segment pair is 20 67 24 01. Reported, not
            // rejected: the same object can be addressed with 16-bit logical
            // segments, and refusing an encoding we simply did not anticipate would
            // turn a working client into a silent failure. A line in the log is
            // enough to find it if one ever appears.
            if (pathBytes != 4 ||
                buf[offset] != 0x20 || buf[offset + 1] != 0x67 ||
                buf[offset + 2] != 0x24 || buf[offset + 3] != 0x01)
            {
                if (Interlocked.Exchange(ref _unexpectedPathWarned, 1) == 0)
                {
                    Logger.Warn(this, "ExtractAndDispatchPCCC: Execute PCCC addressed to an unexpected CIP path - " +
                                      "handling anyway. Further occurrences on this connection are not logged.");
                }
            }

            offset += pathBytes;

            // ── Request ID ──────────────────────────────────────────────────
            // Length-prefixed: requestIdSize counts itself (1) + vendor_id (2) +
            // serial (4) = 7 at minimum, but a client may append further
            // identifying bytes and the spec allows it. Accept any size at or
            // above the minimum and echo the whole section back verbatim —
            // WritePcccReplyHeader writes it length-agnostically.
            //
            // Demanding exactly 7 dropped such a request silently. RSLinx and
            // libplctag both send 7, which is why it never showed up.
            if (offset >= itemEnd || offset >= buf.Length) return;
            byte requestIdSize = buf[offset++];

            if (requestIdSize < 7)
            {
                Logger.Warn(this, $"ExtractAndDispatchPCCC: requestIdSize {requestIdSize} below the 7-byte minimum - dropping");
                return;
            }

            int skipBytes = requestIdSize - 1; // since we already consumed the size byte
            if (offset + skipBytes > buf.Length || offset + skipBytes > itemEnd) return;

            // Store Request ID in the context object (not in instance field).
            context.RequestId = new byte[requestIdSize];
            context.RequestId[0] = requestIdSize;
            for (int k = 1; k < requestIdSize; k++)
                context.RequestId[k] = buf[offset + k - 1];
            offset += skipBytes;

            // ── PCCC command header ──────────────────────────────────────────
            // Minimum: CMD(1) STS(1) TNS(2) FUNC(1) = 5 bytes.
            if (offset + 5 > buf.Length || offset + 5 > itemEnd)
            {
                Logger.Info(this, $"ExtractAndDispatchPCCC: truncated PCCC header at offset {offset}");
                return;
            }

            byte   pcccCmd  = buf[offset++];
            byte   pcccSts  = buf[offset++];
            ushort pcccTns  = (ushort)(buf[offset] | (buf[offset + 1] << 8)); offset += 2;
            byte   pcccFunc = buf[offset++];

            int remaining = Math.Max(0, itemEnd - offset);

            // ── Build PCCC-style PDU ──────────────────────────────────────────
            bool hasFunc = pcccFunc != 0 || remaining > 0;
            int  pduLen  = 6 + (hasFunc ? 1 : 0) + remaining;
            var  pdu     = new byte[pduLen];

            pdu[0] = 0x01;   // DST — this gateway's node
            pdu[1] = 0x01;   // SRC — client node
            pdu[2] = pcccCmd;
            pdu[3] = pcccSts;
            pdu[4] = (byte)(pcccTns & 0xFF);
            pdu[5] = (byte)((pcccTns >> 8) & 0xFF);

            int pduOff = 6;
            if (hasFunc)    pdu[pduOff++] = pcccFunc;
            if (remaining > 0)
                Array.Copy(buf, offset, pdu, pduOff, Math.Min(remaining, buf.Length - offset));

            Logger.Info(this, $"PCCC dispatch: CMD=0x{pcccCmd:X2} TNS=0x{pcccTns:X4} FNC=0x{pcccFunc:X2} data={remaining}B");

            _transport.IncrementFramesProcessed();

            // Raise PduReceived with the context object as clientContext.
            _transport.PduReceived?.Invoke(this, (pdu, context));
        }

        // ── Response senders ─────────────────────────────────────────────────

        /// <summary>
        /// Serialized entry point called by <see cref="EIPServerTransport.SendResponse"/>.
        /// Acquires _sendLock before delegating to SendResponseAsync() to guarantee
        /// FIFO ordering of outgoing responses within a single client session.
        ///
        /// Using a SemaphoreSlim(1,1) here ensures that if two requests complete on
        /// the thread pool at the same time, their responses are written to the socket
        /// in the order they were queued, not interleaved.
        ///
        /// Exceptions from the send path are caught and logged here so the caller
        /// (EIPTransport.SendResponse) can safely fire-and-forget this task.
        /// </summary>
        /// <param name="pdu">PDU to send (the PLC's reply, routed back by Gateway)</param>
        /// <param name="context">Request context containing SenderContext and RequestId</param>
        public async Task SendSerializedAsync(byte[] pdu, EIPRequestContext context)
        {
            if (_disposed || _transport.IsDisposing) return;

            await _sendLock.WaitAsync().ConfigureAwait(false);
            try
            {
                await SendResponseAsync(pdu, context).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Logger.Warn(this, $"SendSerializedAsync failed for session 0x{_sessionHandle:X8}: {ex.Message}");
            }
            finally
            {
                _sendLock.Release();
            }
        }

        /// <summary>
        /// Routes to <see cref="SendConnectedResponse"/> or
        /// <see cref="SendUnconnectedResponse"/> depending on whether a
        /// Forward Open connection has been established.
        /// Called exclusively from <see cref="SendSerializedAsync"/> which
        /// holds _sendLock for the duration of this call.
        /// </summary>
        /// <param name="pdu">PDU to send (the PLC's reply, routed back by Gateway)</param>
        /// <param name="context">Request context containing SenderContext and RequestId</param>
        private async Task SendResponseAsync(byte[] pdu, EIPRequestContext context)
        {
            if (_disposed || _transport.IsDisposing) return;

            Logger.Info(this, $"SendResponseAsync: PDU length={pdu.Length}");

            if (context.IsConnectedAtReceive)
                await SendConnectedResponse(pdu, context).ConfigureAwait(false);
            else
                await SendUnconnectedResponse(pdu, context).ConfigureAwait(false);
        }

        /// <summary>
        /// Builds and sends a PCCC response inside a CIP Unconnected Send reply
        /// (EIP command 0x006F). CPF layout: NULL Address Item + Unconnected Data Item.
        /// </summary>
        /// <param name="pdu">PDU to send</param>
        /// <param name="context">Request context (contains SenderContext and RequestId)</param>
        private async Task SendUnconnectedResponse(byte[] pdu, EIPRequestContext context)
        {
            using var ms = new MemoryStream();
            using var w  = new BinaryWriter(ms);

            WriteEipHeader(w, EIP_UNCONNECTED_SEND, _sessionHandle, context.SenderContext);
            WriteSendCpfHeader(w, 2);
            WriteNullAddressItem(w);

            w.Write(CPF_ITEM_UNCONNECTED_DATA);
            long lenPos    = ms.Position; w.Write((ushort)0);
            long dataStart = ms.Position;

            WritePcccReplyHeader(w, pdu, context.RequestId);

            // Data payload — reply PDU layout as routed back by Gateway:
            //   [DST, SRC, CMD, STS, TNS_LO, TNS_HI, DATA...]
            // Data bytes start at offset 6; the PLC's reply carries no FUNC byte.
            const int dataOffset = 6;
            if (pdu.Length > dataOffset)
                w.Write(pdu, dataOffset, pdu.Length - dataOffset);

            long dataEnd = ms.Position;
            ms.Seek(lenPos, SeekOrigin.Begin);
            w.Write((ushort)(dataEnd - dataStart));
            ms.Seek(dataEnd, SeekOrigin.Begin);

            FixEipLength(ms, w);
            await FlushAsync(ms).ConfigureAwait(false);
        }

        /// <summary>
        /// Builds and sends a PCCC response inside a CIP Connected Send reply
        /// (EIP command 0x0070). CPF layout: Connected Address Item + Connected Data Item.
        /// </summary>
        /// <param name="pdu">PDU to send</param>
        /// <param name="context">Request context (contains SenderContext and RequestId)</param>
        private async Task SendConnectedResponse(byte[] pdu, EIPRequestContext context)
        {
            var conn = context.Connection;
            if (conn == null) return;

            using var ms = new MemoryStream();
            using var w  = new BinaryWriter(ms);

            WriteEipHeader(w, EIP_CONNECTED_SEND, _sessionHandle, context.SenderContext);
            WriteSendCpfHeader(w, 2);

            // Connected Address Item carries the T→O connection ID.
            w.Write(CPF_ITEM_CONNECTED_ADDRESS);
            w.Write((ushort)4);
            w.Write(conn.OrigConnectionId);

            // Connected Data Item.
            w.Write(CPF_ITEM_CONNECTED_DATA);
            long lenPos    = ms.Position; w.Write((ushort)0);
            long dataStart = ms.Position;

            // Connection sequence number increments monotonically; cast to ushort
            // so it wraps at 0xFFFF as per EIP spec (intentional truncation).
            w.Write((ushort)(Interlocked.Increment(ref conn.SequenceNumber) & 0xFFFF));

            WritePcccReplyHeader(w, pdu, context.RequestId);

                        const int dataOffset = 6;
            if (pdu.Length > dataOffset)
                w.Write(pdu, dataOffset, pdu.Length - dataOffset);

            long dataEnd = ms.Position;
            ms.Seek(lenPos, SeekOrigin.Begin);
            w.Write((ushort)(dataEnd - dataStart));
            ms.Seek(dataEnd, SeekOrigin.Begin);

            FixEipLength(ms, w);
            await FlushAsync(ms).ConfigureAwait(false);
        }

        /// <summary>
        /// Writes the CIP Execute PCCC reply header (service 0xCB) and echoes
        /// the Request ID bytes from the context.
        /// <para>
        /// Layout (CIP Execute PCCC reply, per ODVA/AB PCCC):
        ///   reply_code     (1) = 0xCB
        ///   reserved       (1) = 0x00
        ///   general_status (1) = 0x00 (ok)
        ///   status_size    (1) = 0x00
        ///   request_id     (N) = echoed from request context
        ///   pccc_command   (1)
        ///   pccc_status    (1)
        ///   pccc_seq_num   (2)
        /// </para>
        /// </summary>
        /// <param name="w">BinaryWriter to write to</param>
        /// <param name="pdu">PDU containing response fields</param>
        /// <param name="requestId">Request ID bytes from the context (to echo)</param>
        private void WritePcccReplyHeader(BinaryWriter w, byte[] pdu, byte[]? requestId)
        {
            w.Write((byte)0xCB);   // Execute PCCC reply service code (0x4B | 0x80)
            w.Write((byte)0x00);   // Reserved
            w.Write(CIP_STATUS_OK);
            w.Write((byte)0x00);   // Additional status size = 0

            // Echo the Request ID that was stored in the request context.
            if (requestId != null)
            {
                w.Write(requestId);
            }
            else
            {
                // Fallback: use our own vendor identity when no Request ID was saved.
                w.Write((byte)7);
                w.Write(VENDOR_ID);
                w.Write(VENDOR_SERIAL_NUMBER);
            }

            // PCCC response fields (echoed from PDU).
            w.Write(pdu[2]);                                    // CMD
            w.Write(pdu[3]);                                    // STS
            w.Write((ushort)(pdu[4] | (pdu[5] << 8)));         // TNS
        }

        // ── Error reply ──────────────────────────────────────────────────────

        /// <summary>
        /// Sends an EIP error response for commands that cannot be fulfilled.
        /// Per EIP Vol 2, §2-3: the Status field in the header carries the error
        /// code; the payload length is zero.
        /// </summary>
        /// <param name="command">Command code to echo in response</param>
        /// <param name="errorStatus">Status code (EIP_STATUS_*)</param>
        /// <param name="context">Request context (contains SenderContext for echo)</param>
        private async Task SendErrorReply(ushort command, uint errorStatus, EIPRequestContext context)
        {
            var response = new byte[24];
            response[0] = (byte)(command & 0xFF);
            response[1] = (byte)((command >> 8) & 0xFF);
            // Length = 0 (bytes 2-3 remain zero)
            response[4] = (byte)(_sessionHandle & 0xFF);
            response[5] = (byte)((_sessionHandle >> 8)  & 0xFF);
            response[6] = (byte)((_sessionHandle >> 16) & 0xFF);
            response[7] = (byte)((_sessionHandle >> 24) & 0xFF);
            // Error status at bytes 8-11
            response[8]  = (byte)(errorStatus & 0xFF);
            response[9]  = (byte)((errorStatus >> 8)  & 0xFF);
            response[10] = (byte)((errorStatus >> 16) & 0xFF);
            response[11] = (byte)((errorStatus >> 24) & 0xFF);
            BitConverter.TryWriteBytes(response.AsSpan(12), context.SenderContext);

            await SendRawResponse(response, response.Length).ConfigureAwait(false);
        }

        // ── Stream flush helper ───────────────────────────────────────────────

        private async Task FlushAsync(MemoryStream ms)
        {
            long end = ms.Position;
            byte[] bytes = ms.GetBuffer();
            await SendRawResponse(bytes, (int)end).ConfigureAwait(false);
        }

        // ── IDisposable ───────────────────────────────────────────────────────

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _sendLock.Dispose();
            try { _stream.Close(); } catch { }
            try { _tcp.Close();    } catch { }
        }
    }
}
