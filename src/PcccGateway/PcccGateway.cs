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

using System.Collections.Concurrent;
using PcccGateway.Common;
using PcccGateway.Interface;
using PcccGateway.Server;

namespace PcccGateway;

/// <summary>
/// Protocol gateway that bridges between:
///   - EtherNet/IP (EIP) clients (RSLinx, libplctag, pycomm3, etc.)
///   - Legacy PLCs via DF1 (serial) or CSPv4 (TCP/2222)
///
/// The gateway forwards PCCC PDUs transparently without interpreting
/// the PCCC payload, enabling any EIP client to communicate with
/// legacy PLCs that only support DF1 or CSPv4.
/// </summary>
public class Gateway : IDisposable
{
    private readonly ITransport _plcTransport;
    private readonly EIPServerTransport _eipTransport;

    // ─── Request correlation ───
    // A single legacy PLC link is shared by every EIP client, but the PCCC
    // transaction number (TNS) that correlates a reply to its request is chosen
    // by the *client*. Two clients can pick the same TNS, and one client can
    // reuse a TNS before its previous reply arrives — either would misroute or
    // drop replies if we keyed correlation on the client's TNS directly.
    //
    // So the gateway allocates its OWN 16-bit TNS for every outstanding request,
    // rewrites it into the outgoing PDU, and remembers the client's original
    // TNS. When the PLC reply comes back on the gateway TNS we restore the
    // client's TNS before handing it to the originating client. Gateway TNS
    // values are unique across all clients, so cross-client collisions cannot
    // happen and same-client reuse is harmless.
    internal sealed class Pending
    {
        public required object Context;      // originating EIPRequestContext
        public required ushort OriginalTns;  // client's TNS, restored in the reply
        public required long   StampTicks;   // Environment.TickCount64 at send time
    }

    internal readonly ConcurrentDictionary<ushort, Pending> _pending = new();
    internal int _tnsCounter;                 // wraps naturally through the ushort range
    private readonly object _tnsLock = new object();
    private Timer? _evictTimer;

    /// <summary>
    /// Maximum time (ms) a request may wait for a PLC reply before its
    /// correlation entry is evicted. Prevents an unbounded leak when the PLC
    /// never answers.
    /// </summary>
    public int PendingTimeoutMs { get; set; } = 10_000;

    // ─── PLC link supervision / auto-reconnect ───
    // The PLC link (serial or TCP) can drop at any time — a cable is pulled, a
    // switch reboots, the PLC power-cycles. A single supervisor task owns the
    // link's open/reconnect lifecycle so Open() is never called from two threads
    // at once. On failure it retries with exponential backoff; the send path
    // wakes it immediately (instead of waiting out the backoff) the moment it
    // observes a dead link, and fails the current request fast so EIP clients
    // get a prompt timeout rather than hanging.
    private CancellationTokenSource? _linkCts;
    private Task? _linkTask;
    private readonly ManualResetEventSlim _linkWake = new(false);

    /// <summary>Initial reconnect backoff delay in milliseconds.</summary>
    public int ReconnectInitialDelayMs { get; set; } = 1_000;

    /// <summary>Maximum reconnect backoff delay in milliseconds.</summary>
    public int ReconnectMaxDelayMs { get; set; } = 30_000;

    private volatile bool _running;
    private volatile bool _disposed;

    /// <summary>
    /// Raised when a PDU is forwarded from EIP to the PLC transport.
    /// </summary>
    public event EventHandler<(byte[] pdu, ushort tns)>? PduForwarded;

    /// <summary>
    /// Raised when a PDU is forwarded from the PLC transport to EIP.
    /// </summary>
    public event EventHandler<(byte[] pdu, ushort tns)>? PduReplyForwarded;

    /// <summary>
    /// Creates a new gateway instance.
    /// </summary>
    /// <param name="plcTransport">
    /// Transport to the legacy PLC (DF1FullDuplexTransport, DF1HalfDuplexTransport,
    /// or CSPTransport). Must already be configured with appropriate settings.
    /// </param>
    /// <param name="eipPort">TCP port for the EIP server (default 44818).</param>
    public Gateway(ITransport plcTransport, int eipPort = 44818, System.Net.IPAddress? bindAddress = null)
    {
        _plcTransport = plcTransport ?? throw new ArgumentNullException(nameof(plcTransport));
        _eipTransport = new EIPServerTransport(eipPort, bindAddress);

        _eipTransport.PduReceived += OnEipPduReceived;
        _plcTransport.FrameReceived += OnPlcFrameReceived;

        // Log the actual bytes on the PLC wire so a full transaction is visible
        // end to end. Without this, the PLC-side hop (DF1/CSP/EIP) never appears
        // at the byte level and the log stops at the gateway. The sender is the
        // transport itself, so the category tag (DFU/DFS/CSP/EIP/P) is correct
        // automatically, and the arrows state the direction unambiguously.
        _plcTransport.RawFrameSent     += (sndr, f) => Logger.Hex(sndr, "TX →PLC:", f, f.Length);
        _plcTransport.RawFrameReceived += (sndr, f) => Logger.Hex(sndr, "RX ←PLC:", f, f.Length);
    }

    /// <summary>
    /// Starts the gateway: opens the PLC transport and starts the EIP server.
    /// </summary>
    public void Start()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(Gateway));

        _running = true;

        // Start the EIP server first so clients can connect even while the PLC
        // link is still coming up (they will simply time out until it is ready).
        _eipTransport.Start();

        _evictTimer = new Timer(_ => EvictStale(), null, 1000, 1000);

        // Launch the link supervisor: it performs the initial connect and all
        // subsequent reconnects. Start() no longer throws if the PLC is not yet
        // reachable — the supervisor keeps retrying in the background.
        _linkCts = new CancellationTokenSource();
        _linkTask = Task.Run(() => LinkSupervisorLoop(_linkCts.Token));

        Logger.Info(this, "PcccGateway started");
    }

    /// <summary>
    /// Stops the gateway gracefully.
    /// </summary>
    public void Stop()
    {
        _running = false;

        // Stop the supervisor before closing the transport so it does not try to
        // reconnect during shutdown.
        _linkCts?.Cancel();
        _linkWake.Set();
        try { _linkTask?.Wait(2_000); } catch { /* ignore shutdown races */ }
        _linkCts?.Dispose();
        _linkCts  = null;
        _linkTask = null;

        _evictTimer?.Dispose();
        _evictTimer = null;
        _eipTransport.Stop();
        _plcTransport.Close();
        _pending.Clear();
        Logger.Info(this, "PcccGateway stopped");
    }

    // ─── Event handlers ─────────────────────────────────────────────

    private void OnEipPduReceived(object? sender, (byte[] pdu, object context) args)
    {
        var (pdu, context) = args;
        if (pdu.Length < 6) return;

        // Fail fast when the PLC link is down: drop the request and nudge the
        // supervisor to reconnect, rather than blocking or queueing. The EIP
        // client will time out and retry, which is the correct behaviour for a
        // transparent gateway.
        if (!_plcTransport.IsOpen)
        {
            Logger.Warn(this, "PLC link down — request dropped");
            _linkWake.Set();
            return;
        }

        ushort originalTns = (ushort)(pdu[4] | (pdu[5] << 8));

        // Allocate a gateway-unique TNS, register the pending entry, then
        // rewrite the outgoing PDU so the PLC sees the gateway TNS. This is
        // what lets a single PLC link serve many EIP clients without their
        // TNS values colliding (see the Pending remarks above).
        ushort gwTns = AllocateGatewayTns(context, originalTns);
        pdu[4] = (byte)(gwTns & 0xFF);
        pdu[5] = (byte)((gwTns >> 8) & 0xFF);

        Logger.Hex(this, $"EIP → PLC gwTNS=0x{gwTns:X4} (client TNS=0x{originalTns:X4})", pdu, pdu.Length);

        try
        {
            _plcTransport.SendFrame(pdu);
            PduForwarded?.Invoke(this, (pdu, gwTns));
        }
        catch (Exception ex)
        {
            Logger.Warn(this, $"SendFrame to PLC failed: {ex.Message}");
            _pending.TryRemove(gwTns, out _);
            // A send failure usually means the link just died; wake the
            // supervisor so it re-checks and reconnects without waiting out the
            // backoff.
            _linkWake.Set();
        }
    }

    private void OnPlcFrameReceived(object? sender, byte[] replyPdu)
    {
        if (_disposed) return;   // a late frame after teardown must not be routed
        if (replyPdu.Length < 6) return;

        ushort gwTns = (ushort)(replyPdu[4] | (replyPdu[5] << 8));

        if (_pending.TryRemove(gwTns, out Pending? pend))
        {
            // Identity-probe reply: complete the probe instead of routing to a client.
            if (pend.Context is TaskCompletionSource<byte[]> probeTcs)
            {
                probeTcs.TrySetResult(replyPdu);
                return;
            }

            // Restore the client's original TNS so the reply matches the TNS
            // the client actually sent.
            replyPdu[4] = (byte)(pend.OriginalTns & 0xFF);
            replyPdu[5] = (byte)((pend.OriginalTns >> 8) & 0xFF);

            Logger.Hex(this, $"PLC → EIP client TNS=0x{pend.OriginalTns:X4} (gwTNS=0x{gwTns:X4})", replyPdu, replyPdu.Length);
            _eipTransport.SendResponse(replyPdu, pend.Context);
            PduReplyForwarded?.Invoke(this, (replyPdu, pend.OriginalTns));
        }
        else
        {
            Logger.Warn(this, $"Received reply for unknown/expired gwTNS=0x{gwTns:X4} — ignored");
        }
    }

    /// <summary>
    /// Allocates a gateway-unique 16-bit TNS not currently outstanding and
    /// registers the pending correlation entry. Serialized so two threads never
    /// hand out the same value.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when the TNS pool is exhausted (all 65535 values in use).</exception>
    internal ushort AllocateGatewayTns(object context, ushort originalTns)
    {
        lock (_tnsLock)
        {
            ushort tns;
            int attempts = 0;
            // Skip values already in flight. The pending map is bounded by the
            // number of concurrent outstanding requests, far below 65536, so
            // this loop terminates quickly. However, add a safety counter to
            // prevent an infinite loop if the map somehow becomes full.
            do
            {
                tns = unchecked((ushort)Interlocked.Increment(ref _tnsCounter));
                if (++attempts > 65535)
                    throw new InvalidOperationException("Gateway TNS pool exhausted. Too many pending requests.");
            }
            while (tns == 0 || _pending.ContainsKey(tns));

            _pending[tns] = new Pending
            {
                Context     = context,
                OriginalTns = originalTns,
                StampTicks  = Environment.TickCount64
            };
            return tns;
        }
    }

    /// <summary>
    /// Evicts correlation entries whose PLC reply never arrived within
    /// <see cref="PendingTimeoutMs"/>, so a silent PLC cannot leak memory.
    /// Uses a snapshot of keys to avoid modifying the collection
    /// while enumerating it, which would throw InvalidOperationException.
    /// </summary>
    internal void EvictStale()
    {
        if (_disposed) return;
        long now = Environment.TickCount64;

        // Take a snapshot of stale requests and their pending values so a newer
        // request reusing the same gwTNS is not evicted accidentally.
        var staleEntries = _pending
            .Where(kv => now - kv.Value.StampTicks > PendingTimeoutMs)
            .ToList();

        foreach (var kvp in staleEntries)
        {
            if (_pending.TryRemove(kvp))
            {
                Logger.Warn(this, $"Evicted stale gwTNS=0x{kvp.Key:X4} (no PLC reply in {PendingTimeoutMs} ms)");
            }
        }
    }

    // ─── PLC link supervisor ─────────────────────────────────────────

    /// <summary>
    /// Owns the PLC transport's connect/reconnect lifecycle. Runs on a single
    /// background task so <see cref="ITransport.Open"/> is never called
    /// concurrently. Connects on start, then watches the link and reconnects
    /// with exponential backoff whenever it goes down.
    /// </summary>
    private void LinkSupervisorLoop(CancellationToken ct)
    {
        int delay = ReconnectInitialDelayMs;

        while (_running && !ct.IsCancellationRequested)
        {
            if (!_plcTransport.IsOpen)
            {
                try
                {
                    _plcTransport.Open();
                    delay = ReconnectInitialDelayMs;   // reset backoff on success
                    Logger.Info(this, "PLC transport connected");
                    TryDiscoverIdentity(ct);
                }
                catch (Exception ex)
                {
                    Logger.Warn(this, $"PLC connect failed: {ex.Message} — retrying in {delay} ms");
                    if (WaitOrCancel(delay, ct)) break;
                    delay = Math.Min(delay * 2, ReconnectMaxDelayMs);
                    continue;
                }
            }

            // Connected: sleep until a send failure wakes us or the periodic
            // poll interval elapses, then re-check IsOpen.
            _linkWake.Reset();
            if (WaitOrCancel(1_000, ct)) break;
        }
    }

    /// <summary>
    /// Waits up to <paramref name="ms"/> for the wake signal. Returns true if the
    /// gateway is shutting down (cancelled), false if it woke normally.
    /// </summary>
    private bool WaitOrCancel(int ms, CancellationToken ct)
    {
        try
        {
            _linkWake.Wait(ms, ct);
        }
        catch (OperationCanceledException)
        {
            return true;   // shutdown requested
        }
        return ct.IsCancellationRequested || !_running;
    }

    // ─── Dynamic PLC identity discovery ──────────────────────────────

    /// <summary>
    /// Probes the connected PLC for its identity and advertises it to EIP clients,
    /// so RSLinx and friends see the real processor (a PLC), not a bridge. Runs on
    /// every successful (re)connect, so if the PLC behind the gateway is swapped —
    /// which drops and re-establishes the link — the advertised identity follows the
    /// new hardware. The last-known PLC identity is retained while the transport is
    /// closed and reconnection is attempted.
    ///
    /// If the probe fails due to no response or transport error, the PLC transport is
    /// closed to force a reconnect. This prevents the gateway from hanging
    /// indefinitely when the PLC is unresponsive but the TCP connection remains open.
    /// </summary>
    private void TryDiscoverIdentity(CancellationToken ct)
    {
        try
        {
            byte[]? payload = ProbeDiagnosticStatus(ct);
            if (payload != null && payload.Length > 0)
            {
                Logger.Hex(this, "Diagnostic Status", payload, payload.Length);
                ApplyDiscoveredIdentity(payload);   // updates identity if the PLC changed
            }
            else if (payload != null)
            {
                Logger.Warn(this, "Identity discovery: PLC rejected diagnostic probe — retaining last-known identity");
            }
            else
            {
                Logger.Info(this, "Identity discovery: no PLC response — forcing reconnect");
                // Probe failed (timeout or no response). Close the transport to trigger
                // a full reconnect cycle, which will re-run identity discovery.
                _plcTransport.Close();
            }
        }
        catch (Exception ex)
        {
            Logger.Warn(this, $"Identity discovery error: {ex.Message}");
            // On any exception during discovery, close the transport to attempt recovery.
            try { _plcTransport.Close(); } catch { }
        }
    }

    /// <summary>
    /// Sends PCCC Get Diagnostic Status (CMD 0x06, FNC 0x03) to the PLC using the
    /// gateway's own TNS correlation and returns the reply's DATA payload, or null
    /// on timeout/error.
    /// </summary>
    private byte[]? ProbeDiagnosticStatus(CancellationToken ct, int timeoutMs = 3000)
    {
        var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        ushort gwTns = AllocateGatewayTns(tcs, 0);

        // Inner PCCC frame: DST SRC CMD=0x06 STS=0 TNS_LO TNS_HI FNC=0x03
        byte[] frame =
        {
            0x01, 0x00, 0x06, 0x00,
            (byte)(gwTns & 0xFF), (byte)((gwTns >> 8) & 0xFF),
            0x03
        };

        try
        {
            _plcTransport.SendFrame(frame);
        }
        catch (Exception ex)
        {
            Logger.Warn(this, $"Identity probe send failed: {ex.Message}");
            _pending.TryRemove(gwTns, out _);
            return null;
        }

        try
        {
            if (tcs.Task.Wait(timeoutMs, ct))
            {
                byte[] reply = tcs.Task.Result;
                // reply = [DST SRC CMD STS TNS_LO TNS_HI DATA...]; DATA begins at offset 6.
                // The Get Diagnostic Status reply (CMD 0x46) carries NO FNC byte between
                // TNS and DATA — verified against a real PLC-5/40E Wireshark capture
                // (reply data starts "06 EB 4B ..." right after TNS) and a live
                // MicroLogix 1400 trace (DATA begins "00 EE 4A 9F ..." at offset 6).
                // STS (offset 3) must be 0 — an error reply's trailing bytes are status/echo
                // data, not diagnostic data, and must not be parsed as an identity.
                if (reply.Length > 6 && reply[3] == 0x00)
                    return reply[6..];
                if (reply.Length > 3 && reply[3] != 0x00)
                {
                    Logger.Warn(this, $"Identity probe: PLC returned STS=0x{reply[3]:X2} — ignoring");
                    return Array.Empty<byte>();
                }
                return null;
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown in progress: abandon the probe promptly so Stop() does not race
            // Close()/Clear() against a supervisor thread still blocked here.
            _pending.TryRemove(gwTns, out _);
            return null;
        }

        _pending.TryRemove(gwTns, out _);
        Logger.Warn(this, "Identity probe timed out");
        return null;
    }

    // EDS-derived identity table: PCCC processor type → CIP (Product Type, Product
    // Code, Revision, Name). Values are taken from Rockwell EDS files — authoritative,
    // because the PCCC processor-type namespace and the CIP Product-Code namespace are
    // NOT consistent (e.g. PLC-5/40E is PCCC 0x4B but CIP Product Code 23; SLC-5/05
    // happens to match, MicroLogix 1400 does not). Product Type also varies (12 vs 14),
    // so nothing is hardcoded here.
    // NOTE: the PLC-5 expansion byte and the SLC/MicroLogix processor type are
    // DIFFERENT namespaces — the same byte can mean different things (e.g. 0x15 is
    // PLC-5/40B on a PLC-5 but an SLC-5/05 variant on an SLC). They must therefore
    // be kept in separate tables and selected by family, never looked up by byte
    // value alone.
    private static readonly Dictionary<byte, (ushort type, ushort code, byte revMaj, byte revMin, string name)> Plc5Identity = new()
    {
        // PLC-5 Ethernet (1785-Lx0E, series C–E) — keyed by expansion byte
        [0x4A] = (14, 22, 1, 0, "PLC-5/20E"),
        [0x4B] = (14, 23, 1, 0, "PLC-5/40E"),
        [0x59] = (14, 24, 1, 0, "PLC-5/80E"),
    };

    private static readonly Dictionary<byte, (ushort type, ushort code, byte revMaj, byte revMin, string name)> SlcMlIdentity = new()
    {
        // MicroLogix — keyed by processor type
        [0x9F] = (14, 90,  2, 0, "MicroLogix 1400"),
        [0x90] = (14, 90,  2, 0, "MicroLogix 1400"),
        [0xB9] = (12, 185, 2, 0, "MicroLogix 1100"),
        // SLC 5/05 (1747-L55x) — Comms-Adapter product-type variants
        [0xB0] = (12, 176, 3, 0, "SLC 5/05"),
        [0xB1] = (12, 177, 3, 0, "SLC 5/05"),
        [0xB2] = (12, 178, 3, 0, "SLC 5/05"),
        // SLC 5/05 — PLC product-type variants
        [0x13] = (14, 19,  3, 0, "SLC 5/05"),
        [0x14] = (14, 20,  3, 6, "SLC 5/05"),
        [0x15] = (14, 21,  3, 0, "SLC 5/05"),
        // Older SLC 500 (5/01–5/04) have NO native EtherNet/IP — EIP arrived with the
        // 5/05, so they are presented with the SLC 5/05 identity (Type 14, Code 20).
        // The real processor is still revealed by the client's own PCCC query.
        [0x88] = (14, 20,  3, 6, "SLC 5/01"),
        [0x89] = (14, 20,  3, 6, "SLC 5/02"),
        [0x49] = (14, 20,  3, 6, "SLC 5/03"),
        [0x5B] = (14, 20,  3, 6, "SLC 5/04"),
    };

    /// <summary>A resolved CIP identity for the EIP server to advertise.</summary>
    internal readonly record struct PlcIdentity(
        ushort DeviceType, ushort ProductCode, byte RevMajor, byte RevMinor, string Name);

    /// <summary>
    /// Pure resolver: maps a Get Diagnostic Status DATA payload to a CIP identity,
    /// using the EDS-derived, family-specific tables (AB Pub 1770-6.5.16). Returns
    /// null only when the payload is too short to classify. Extracted from the
    /// side-effecting apply path so it can be unit-tested against sample captures.
    /// </summary>
    internal static PlcIdentity? ResolveIdentity(byte[] payload)
    {
        if (payload.Length < 5) return null;

        // Family from the type-extender byte, processor type from a family-specific
        // offset. Verified against real hardware captures:
        //   PLC-5/40E : payload = 06 EB 4B ...  → byte[1]=0xEB (nibble 0xB) → expansion byte[2]=0x4B
        //   ML 1400   : payload = 00 EE 4A 9F ...→ byte[1]=0xEE (nibble 0xE) → proc type byte[3]=0x9F
        byte typeExtender = payload[1];
        bool isPlc5 = (typeExtender & 0x0F) == 0x0B;   // 0xEB → PLC-5; 0xEE → SLC/MicroLogix

        byte procType = isPlc5
            ? payload[2]                                       // PLC-5: expansion byte
            : (payload.Length > 3 ? payload[3] : (byte)0);     // SLC/ML: extended processor type

        // Look up in the family-specific table (the PLC-5 and SLC/ML byte namespaces
        // overlap, e.g. 0x15, so the byte must never be looked up without its family).
        var table = isPlc5 ? Plc5Identity : SlcMlIdentity;
        if (table.TryGetValue(procType, out var id))
            return new PlcIdentity(id.type, id.code, id.revMaj, id.revMin, id.name);

        // Unknown processor type → the family's most representative EtherNet/IP-capable
        // identity, so RSLinx still recognises it (and picks the correct read protocol).
        if (isPlc5)
            return new PlcIdentity(14, 23, 1, 0, "PLC-5");   // → PLC-5/40E

        // Unknown SLC/MicroLogix → SLC 5/05; keep the catalog string it reported.
        int end = Math.Min(16, payload.Length);
        string catalog = end > 5
            ? System.Text.Encoding.ASCII.GetString(payload, 5, end - 5).Trim('\0', ' ')
            : string.Empty;
        string name = string.IsNullOrWhiteSpace(catalog) ? "SLC 5/05" : catalog;
        return new PlcIdentity(14, 20, 3, 6, name);
    }

    private bool ApplyDiscoveredIdentity(byte[] payload)
    {
        if (ResolveIdentity(payload) is not { } id) return false;
        _eipTransport.SetProductIdentity(id.DeviceType, id.ProductCode, id.RevMajor, id.RevMinor, id.Name);
        return true;
    }

    // ─── IDisposable ─────────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
        _eipTransport.Dispose();

        // _linkWake is intentionally NOT disposed. It is touched by the supervisor
        // task (Reset/Wait) and by OnEipPduReceived (Set); Stop() only waits up to
        // 2 s for the supervisor to exit, so disposing here could race a still-live
        // thread into an ObjectDisposedException. As a process-lifetime singleton,
        // leaving the lightweight event to finalization is the race-free choice.
        GC.SuppressFinalize(this);
    }
}
