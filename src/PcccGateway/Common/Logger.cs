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
using PcccGateway.Server;

namespace PcccGateway.Common;

/// <summary>
/// Centralized logging for the PCCC emulator.
/// - Info/Hex respect Logger.Enabled (global switch).
/// - Always/AlwaysHex always write (useful for startup/shutdown/fatal errors).
/// - Category is auto-detected from sender type.
/// - Thread-safe.
/// </summary>
public static class Logger
{
    private static volatile bool _enabled = true;
    public static bool ShowTimestamp { get; set; } = true;
    private static readonly object _lock = new object();
    private static readonly ConcurrentDictionary<Type, string> _categoryCache = new();

    public static bool Enabled
    {
        get => _enabled;
        set => _enabled = value;
    }

    private static void WriteHex(TextWriter writer, byte[] data, int length)
    {
        for (int i = 0; i < length; i++)
        {
            if (i > 0) writer.Write(' ');
            writer.Write(data[i].ToString("X2"));
        }
    }

    private static void WriteLine(string prefix, string message)
    {
        if (ShowTimestamp)
            Console.WriteLine($"{prefix} {DateTime.Now:HH:mm:ss.fff} {message}");
        else
            Console.WriteLine($"{prefix} {message}");
    }

    private static string GetCategory(object? sender)
    {
        if (sender is null) return "SYS";
        Type type = sender.GetType();
        return _categoryCache.GetOrAdd(type, t =>
        {
            if (t == typeof(DF1FullDuplexTransport)) return "DFU";
            if (t == typeof(DF1HalfDuplexTransport)) return "DFS";
            // Frontend (faces EIP clients) vs backend (faces the PLC) must be
            // distinguishable in the log, otherwise an EIP-to-EIP setup shows
            // both hops under the same tag and you cannot tell source from dest.
            if (t == typeof(EIPServerTransport)) return "EIP/S";  // server / client-side
            if (t.Name == "EIPClient") return "EIP/S";            // per-connection, client-side
            if (t == typeof(EIPTransport)) return "EIP/P";        // client transport, PLC-side
            if (t == typeof(CSPTransport)) return "CSP";          // backend only
            if (t.Name == "CSPClient") return "CSP";
            return t.Name;
        });
    }

    /// <summary>Log if Logger.Enabled == true.</summary>
    public static void Info(object? sender, string message)
    {
        if (!Enabled) return;
        lock (_lock)
            WriteLine($"[{GetCategory(sender)}]", message);
    }

    /// <summary>Hex dump if Logger.Enabled == true.</summary>
    public static void Hex(object? sender, string prefix, byte[] data, int length)
    {
        if (!Enabled || length <= 0 || data == null) return;
        if (length > data.Length) length = data.Length;
        lock (_lock)
        {
            if (ShowTimestamp)
                Console.Write($"[{GetCategory(sender)}] {DateTime.Now:HH:mm:ss.fff} {prefix} ");
            else
                Console.Write($"[{GetCategory(sender)}] {prefix} ");
            WriteHex(Console.Out, data, length);
            Console.WriteLine();
        }
    }

    /// <summary>Always log (ignores Logger.Enabled).</summary>
    public static void Always(object? sender, string message)
    {
        lock (_lock)
            WriteLine($"[{GetCategory(sender)}]", message);
    }

    /// <summary>Warn log (ignores Logger.Enabled).</summary>
    public static void Warn(object? sender, string message)
    {
        lock (_lock)
            WriteLine($"[{GetCategory(sender)}]", "[WARN] " + message);
    }

    /// <summary>Always hex dump (ignores Logger.Enabled).</summary>
    public static void AlwaysHex(object? sender, string prefix, byte[] data, int length)
    {
        if (length <= 0 || data == null) return;
        if (length > data.Length) length = data.Length;
        lock (_lock)
        {
            if (ShowTimestamp)
                Console.Write($"[{GetCategory(sender)}] {DateTime.Now:HH:mm:ss.fff} {prefix} ");
            else
                Console.Write($"[{GetCategory(sender)}] {prefix} ");
            WriteHex(Console.Out, data, length);
            Console.WriteLine();
        }
    }
}
