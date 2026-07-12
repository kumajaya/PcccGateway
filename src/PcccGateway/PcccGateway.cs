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
using PcccGateway.Client;
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
    private sealed class Pending
    {
        public required object Context;      // originating EIPRequestContext
        public required ushort OriginalTns;  // client's TNS, restored in the reply
        public required long   StampTicks;   // Environment.TickCount64 at send time
    }

    private readonly ConcurrentDictionary<ushort, Pending> _pending = new();
    private int _tnsCounter;                 // wraps naturally through the ushort range
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
    private bool _disposed;

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
    public Gateway(ITransport plcTransport, int eipPort = 44818)
    {
        _plcTransport = plcTransport ?? throw new ArgumentNullException(nameof(plcTransport));
        _eipTransport = new EIPServerTransport(eipPort);

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
        if (replyPdu.Length < 6) return;

        ushort gwTns = (ushort)(replyPdu[4] | (replyPdu[5] << 8));

        if (_pending.TryRemove(gwTns, out Pending? pend))
        {
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
    private ushort AllocateGatewayTns(object context, ushort originalTns)
    {
        lock (_tnsLock)
        {
            ushort tns;
            // Skip values already in flight. The pending map is bounded by the
            // number of concurrent outstanding requests, far below 65536, so
            // this loop terminates quickly.
            do
            {
                tns = unchecked((ushort)Interlocked.Increment(ref _tnsCounter));
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
    /// </summary>
    private void EvictStale()
    {
        if (_disposed) return;
        long now = Environment.TickCount64;
        foreach (var kv in _pending)
        {
            if (now - kv.Value.StampTicks > PendingTimeoutMs &&
                _pending.TryRemove(kv.Key, out _))
            {
                Logger.Warn(this, $"Evicted stale gwTNS=0x{kv.Key:X4} (no PLC reply in {PendingTimeoutMs} ms)");
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
            return true;
        }
        return ct.IsCancellationRequested || !_running;
    }

    // ─── IDisposable ─────────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
        _eipTransport.Dispose();
        _linkWake.Dispose();
    }
}
