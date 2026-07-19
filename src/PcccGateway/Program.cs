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

using System.Globalization;
using System.IO.Ports;
using PcccGateway.Client;
using PcccGateway.Common;
using PcccGateway.Interface;
using PcccGateway.Server;
using Gateway = PcccGateway.Gateway;

/// <summary>
/// PcccGateway launcher — fully non-interactive; all settings come from the
/// command line so the gateway can run unattended (service, container, CI).
///
/// PLC-side transport modes (this is the backend, facing the legacy PLC):
///   df1        DF1 full-duplex serial (default)
///   df1master  DF1 half-duplex master over RS-485
///   csp        CSPv4 (Client Server Protocol) over TCP
///   eip        EtherNet/IP (PCCC-over-CIP) over TCP
///
/// The frontend is always an EtherNet/IP server (emulating a 1761-NET-ENI)
/// listening on --listen-port (default 44818).
///
/// Examples:
///   dotnet run -- COM2 --baud 19200 --checksum crc
///   dotnet run -- COM3 --mode df1master --target 3 --rs485-mode rts
///   dotnet run -- --mode csp --host 192.168.1.10 --csp-port 2222
///   dotnet run -- --mode eip --host 192.168.1.10
///   dotnet run -- COM2 --quiet
/// </summary>
class Program
{
    /// <summary>
    /// Raised when an option's value cannot be parsed or is out of range.
    /// </summary>
    private sealed class ArgumentParseException : Exception
    {
        public ArgumentParseException(string message) : base(message) { }
    }

    /// <summary>
    /// Parses an integer option, refusing anything that is not one.
    /// </summary>
    /// <remarks>
    /// Every numeric option used to be parsed with a bare
    /// <c>if (int.TryParse(...)) x = v;</c> and no else branch, so a typo left
    /// the default silently in place and the gateway ran with a configuration
    /// nobody had asked for. Worse for values that parse but cannot work:
    /// --baud 0 reached SerialPort.Open(), which throws inside the link
    /// supervisor, which catches it, logs "PLC connect failed - retrying", and
    /// loops forever. An operator watching that sees a link problem, not the
    /// configuration error it actually is.
    /// </remarks>
    private static int ParseInt(string option, string value, int min, int max)
    {
        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed))
            throw new ArgumentParseException($"{option} expects an integer, got '{value}'.");
        if (parsed < min || parsed > max)
            throw new ArgumentParseException($"{option} must be between {min} and {max}, got {parsed}.");
        return parsed;
    }

    static int Main(string[] args)
    {
        // ── Defaults ──────────────────────────────────────────────────────────
        string portName   = "COM2";
        string mode        = "df1";
        int    baud        = 19200;
        Parity parity      = Parity.None;
        string checksum    = "crc";
        int    target      = 1;          // df1master slave node address
        string rs485Mode   = "auto";
        int    rs485Assert = 1;
        int    rs485Deassrt= 5;
        bool   echoSuppr   = false;
        string? host       = null;       // required for csp / eip
        int    cspPort     = 2222;
        int    plcEipPort  = 44818;
        int    listenPort  = EIPServerTransport.EIP_DEFAULT_PORT; // frontend
        System.Net.IPAddress? bindAddr = null; // EIP server bind interface (default all)
        bool   quiet       = false;

        // ── Parse arguments ──────────────────────────────────────────────────
        try
        {
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i].ToLowerInvariant();

                // First bare token (not a flag) is the serial port.
                if (i == 0 && !a.StartsWith("--")) { portName = args[i]; continue; }

                switch (a)
                {
                    case "--mode"     when i + 1 < args.Length: mode = args[++i].ToLowerInvariant(); break;
                    case "--baud"     when i + 1 < args.Length: baud       = ParseInt("--baud", args[++i], 1, 4_000_000); break;
                    case "--target"   when i + 1 < args.Length: target     = ParseInt("--target", args[++i], 1, 254); break;
                    case "--host"     when i + 1 < args.Length: host = args[++i]; break;
                    case "--csp-port" when i + 1 < args.Length: cspPort    = ParseInt("--csp-port", args[++i], 1, 65535); break;
                    case "--plc-eip-port" when i + 1 < args.Length: plcEipPort = ParseInt("--plc-eip-port", args[++i], 1, 65535); break;
                    case "--listen-port"  when i + 1 < args.Length: listenPort = ParseInt("--listen-port", args[++i], 1, 65535); break;
                    case "--bind"         when i + 1 < args.Length:
                        if (!System.Net.IPAddress.TryParse(args[++i], out bindAddr))
                            throw new ArgumentParseException($"--bind expects an IP address, got '{args[i]}'.");
                        if (bindAddr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            // EtherNet/IP's List Identity socket-address field is IPv4-only
                            // (sin_family = AF_INET); an IPv6 bind would corrupt that payload.
                            throw new ArgumentParseException("--bind requires an IPv4 address.");
                        }
                        break;
                    case "--checksum"   when i + 1 < args.Length:
                        checksum = args[++i].ToLowerInvariant();
                        if (checksum is not ("crc" or "bcc"))
                            throw new ArgumentParseException($"--checksum expects crc or bcc, got '{checksum}'.");
                        break;
                    case "--rs485-mode" when i + 1 < args.Length:
                        rs485Mode = args[++i].ToLowerInvariant();
                        if (rs485Mode is not ("auto" or "rts" or "dtr"))
                            throw new ArgumentParseException($"--rs485-mode expects auto, rts or dtr, got '{rs485Mode}'.");
                        break;
                    case "--rs485-assert-delay"   when i + 1 < args.Length: rs485Assert  = ParseInt("--rs485-assert-delay", args[++i], 0, 1000); break;
                    case "--rs485-deassert-delay" when i + 1 < args.Length: rs485Deassrt = ParseInt("--rs485-deassert-delay", args[++i], 0, 1000); break;
                    case "--echo-suppression": echoSuppr = true; break;
                    case "--lsap-control" when i + 1 < args.Length:
                        if (!byte.TryParse(args[++i], NumberStyles.HexNumber, null, out lsapControl))
                            throw new ArgumentParseException($"--lsap-control expects a hex byte, got '{args[i]}'.");
                        break;
                    case "--parity" when i + 1 < args.Length:
                        parity = args[++i].ToLowerInvariant() switch
                        {
                            "none" => Parity.None,
                            "odd"  => Parity.Odd,
                            "even" => Parity.Even,
                            _      => throw new ArgumentParseException($"--parity expects none, odd or even, got '{args[i]}'.")
                        };
                        break;
                    case "--quiet": case "-q": quiet = true; break;
                    case "--help":  case "-h": PrintUsage(); return 0;
                    default:
                        Console.Error.WriteLine($"Unknown or incomplete argument: '{args[i]}'. Use --help.");
                        return 2;
                }
            }
        }
        catch (ArgumentParseException ex)
        {
            Console.Error.WriteLine($"Configuration error: {ex.Message}");
            return 2;
        }

        Console.WriteLine("PcccGateway - PCCC Protocol Gateway");
        Console.WriteLine("Copyright (c) 2026 Ketut Kumajaya");
        Console.WriteLine();

        if (quiet) Logger.Enabled = false;

        var checkSumOpt = checksum == "bcc" ? CheckSumOptions.Bcc : CheckSumOptions.Crc;

        // ── Build the PLC-side transport ─────────────────────────────────────
        ITransport plcTransport;
        try
        {
            switch (mode)
            {
                case "df1":
                    plcTransport = new DF1FullDuplexTransport(portName, baud, parity)
                    {
                        ChecksumType = checkSumOpt
                    };
                    break;

                case "df1master":
                case "df1slave":   // alias
                    plcTransport = new DF1HalfDuplexTransport(portName, baud, parity)
                    {
                        SlaveAddress       = target,
                        ChecksumType       = checkSumOpt,
                        EchoSuppression    = echoSuppr,
                        RtsAssertDelayMs   = rs485Assert,
                        RtsDeassertDelayMs = rs485Deassrt,
                        Rs485Mode = rs485Mode switch
                        {
                            "rts" => DF1HalfDuplexTransport.Rs485ControlMode.Rts,
                            "dtr" => DF1HalfDuplexTransport.Rs485ControlMode.Dtr,
                            _     => DF1HalfDuplexTransport.Rs485ControlMode.Auto
                        }
                    };
                    break;

                case "csp":
                    if (string.IsNullOrEmpty(host))
                        throw new ArgumentException("csp mode requires --host <PLC IP>.");
                    plcTransport = new CSPTransport(host, cspPort, 5000, lsapControl);
                    break;

                case "eip":
                    if (string.IsNullOrEmpty(host))
                        throw new ArgumentException("eip mode requires --host <PLC IP>.");
                    // Guard against pointing the EIP backend at our own frontend.
                    // Loopback is not the only way to reach ourselves: a host that
                    // names one of this machine's own interface addresses loops
                    // just as surely, and that is the easier mistake to make when
                    // copying the gateway's own IP out of a config file.
                    if (IsThisMachine(host) && plcEipPort == listenPort)
                        throw new ArgumentException(
                            $"eip backend targets {host}:{plcEipPort}, which is this machine on the " +
                            $"same port as --listen-port ({listenPort}) — this would loop the gateway " +
                            "into its own server. Use a different --plc-eip-port or --listen-port.");
                    plcTransport = new EIPTransport(host, plcEipPort, 5000);
                    break;

                default:
                    Console.Error.WriteLine($"Unknown --mode '{mode}'. Valid: df1, df1master, csp, eip.");
                    return 2;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Configuration error: {ex.Message}");
            return 2;
        }

        // ── Start the gateway ────────────────────────────────────────────────
        Gateway? gateway = null;
        try
        {
            gateway = new Gateway(plcTransport, eipPort: listenPort, bindAddress: bindAddr);

            gateway.PduForwarded      += (s, e) => Logger.Info(null, $"[FWD] gwTNS=0x{e.tns:X4} len={e.pdu.Length}");
            gateway.PduReplyForwarded += (s, e) => Logger.Info(null, $"[REP] TNS=0x{e.tns:X4} len={e.pdu.Length}");

            try
            {
                gateway.Start();
            }
            catch (System.Net.Sockets.SocketException ex)
            {
                Console.Error.WriteLine(
                    $"Failed to start EIP server on port {listenPort}: {ex.Message}");
                Console.Error.WriteLine(
                    $"Port {listenPort} is likely already in use (another gateway, PCCCEmulator, " +
                    "or RSLinx). Pick a free port with --listen-port <n>.");
                return 3;
            }

            // Configuration summary.
            Console.WriteLine($"      Mode        : {mode}");
            if (mode is "df1" or "df1master" or "df1slave")
            {
                Console.WriteLine($"      Port        : {portName}");
                Console.WriteLine($"      Baud rate   : {baud}");
                Console.WriteLine($"      Parity      : {parity}");
                Console.WriteLine($"      Checksum    : {checkSumOpt}");
                if (mode != "df1")
                {
                    Console.WriteLine($"      Slave node  : {target}");
                    Console.WriteLine($"      RS-485 mode : {rs485Mode}");
                }
            }
            else if (mode == "csp")
            {
                Console.WriteLine($"      PLC host    : {host}:{cspPort}");
                Console.WriteLine($"      LSAP control: 0x{lsapControl:X2}");
            }
            else if (mode == "eip")
            {
                Console.WriteLine($"      PLC host    : {host}:{plcEipPort}");
            }
            Console.WriteLine($"      EIP listen  : {(bindAddr?.ToString() ?? "0.0.0.0")}:{listenPort}");
            Console.WriteLine($"      Logging     : {(quiet ? "Disabled (High Performance)" : "Enabled")}");
            Console.WriteLine();
            Console.WriteLine("Connect your EIP client (RSLinx, libplctag, pycomm3, etc.) to this gateway.");
            Console.WriteLine("Press Ctrl+C to stop.");

            // Block until Ctrl+C (SIGINT/SIGTERM). Works whether stdin is a console
            // or redirected, so the process runs cleanly as a service/container.
            using var stop = new ManualResetEventSlim(false);
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; stop.Set(); };
            AppDomain.CurrentDomain.ProcessExit += (s, e) => stop.Set();
            stop.Wait();

            Console.WriteLine("Gateway stopped.");
            return 0;
        }
        finally
        {
            // Dispose, not just Stop. Stop() only closes the link; the transports
            // do their real teardown in Dispose() — completing callback channels
            // and draining the executor threads DF1 starts for the lifetime of the
            // transport. Nothing used to call it: Gateway disposes the EIP server
            // it creates but not the PLC transport it is handed, and this method
            // stopped at Stop(). The process exiting hid it, which also meant the
            // drain path only ever ran under test.
            //
            // Each step is guarded on its own. Teardown here is exactly where a
            // throw is least acceptable: SerialPortWrapper.Dispose deliberately
            // rethrows a failed port close rather than swallowing it, so an
            // unguarded chain would let that skip the drain and the log flush that
            // follow it. Console.Error rather than Logger, because --quiet has
            // disabled Logger and this is the last chance to say anything.
            try { gateway?.Dispose(); }
            catch (Exception ex) { Console.Error.WriteLine($"Gateway dispose failed: {ex.Message}"); }

            try { plcTransport.Dispose(); }
            catch (Exception ex) { Console.Error.WriteLine($"PLC transport dispose failed: {ex.Message}"); }

            Logger.Shutdown(1000);
        }
    }

    // LSAP control byte for csp mode; hex, default 0x00 (see CSPTransport remarks).
    static byte lsapControl = 0x00;

    /// <summary>
    /// True when the host string names this machine — loopback, or any address
    /// bound to one of its interfaces.
    /// </summary>
    private static bool IsThisMachine(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)) return true;
        if (!System.Net.IPAddress.TryParse(host, out var ip)) return false;
        if (System.Net.IPAddress.IsLoopback(ip)) return true;

        try
        {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    if (ua.Address.Equals(ip))
                        return true;
        }
        catch
        {
            // Interface enumeration can fail in restricted environments. Fall back
            // to the loopback check rather than refusing to start over a guard.
        }
        return false;
    }

    static void PrintUsage()
    {
        Console.WriteLine("PcccGateway - PCCC Protocol Gateway (1761-NET-ENI software replacement)");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  dotnet run -- [port] [options]");
        Console.WriteLine();
        Console.WriteLine("PLC-side transport (backend):");
        Console.WriteLine("  --mode <df1|df1master|csp|eip>  Transport mode (default df1)");
        Console.WriteLine("  [port]                          Serial port for df1/df1master (default COM2)");
        Console.WriteLine("  --baud <n>                      Baud rate (default 19200)");
        Console.WriteLine("  --parity <none|odd|even>        Parity (default none)");
        Console.WriteLine("  --checksum <crc|bcc>            DF1 checksum (default crc)");
        Console.WriteLine("  --target <1-254>                df1master slave node address (default 1)");
        Console.WriteLine("  --rs485-mode <auto|rts|dtr>     RS-485 direction control (default auto)");
        Console.WriteLine("  --rs485-assert-delay <ms>       Delay after enabling driver (default 1)");
        Console.WriteLine("  --rs485-deassert-delay <ms>     Delay before disabling driver (default 5)");
        Console.WriteLine("  --echo-suppression              Discard echoed bytes on RS-485");
        Console.WriteLine("  --host <ip>                     PLC IP address (required for csp/eip)");
        Console.WriteLine("  --csp-port <n>                  PLC CSP port (default 2222)");
        Console.WriteLine("  --plc-eip-port <n>              PLC EtherNet/IP port (default 44818)");
        Console.WriteLine("  --lsap-control <hex>            CSP LSAP control byte (default 00)");
        Console.WriteLine();
        Console.WriteLine("Frontend (EIP server) and misc:");
        Console.WriteLine("  --listen-port <n>               EIP server listen port (default 44818)");
        Console.WriteLine("  --bind <ip>                     Bind EIP server to one interface (default all;");
        Console.WriteLine("                                  note: binding may disable RSLinx broadcast browse)");
        Console.WriteLine("  --quiet, -q                     Disable logging for maximum performance");
        Console.WriteLine("  --help, -h                      Show this help");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  dotnet run -- COM2 --baud 19200 --checksum crc");
        Console.WriteLine("  dotnet run -- COM3 --mode df1master --target 3 --rs485-mode rts");
        Console.WriteLine("  dotnet run -- --mode csp --host 192.168.1.10 --csp-port 2222");
        Console.WriteLine("  dotnet run -- --mode eip --host 192.168.1.10");
        Console.WriteLine("  dotnet run -- COM2 --quiet");
    }
}
