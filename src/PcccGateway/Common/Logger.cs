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

    private const int LogQueueCapacity = 1024;
    private static int _droppedMessages;
    private static readonly BlockingCollection<string> _logQueue = new(new ConcurrentQueue<string>(), LogQueueCapacity);
    private static readonly ConcurrentDictionary<Type, string> _categoryCache = new();
    private static readonly Task _writerTask;
    private static volatile bool _shutdown;

    static Logger()
    {
        // Start a dedicated background thread to write logs.
        _writerTask = Task.Factory.StartNew(() =>
        {
            foreach (var message in _logQueue.GetConsumingEnumerable())
            {
                try
                {
                    Console.WriteLine(message);
                }
                catch (IOException)
                {
                    // Ignore transient console write failures and continue consuming.
                }
                catch (ObjectDisposedException)
                {
                    // Console output has been disposed; stop processing cleanly.
                    break;
                }
            }
        }, TaskCreationOptions.LongRunning);
    }

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

    public static int DroppedMessages => Volatile.Read(ref _droppedMessages);

    private static void EnqueueLog(string line, bool force = false)
    {
        if (_shutdown) return;

        try
        {
            if (force)
            {
                if (!_logQueue.TryAdd(line, millisecondsTimeout: 100))
                    Interlocked.Increment(ref _droppedMessages);
            }
            else if (!_logQueue.TryAdd(line))
            {
                Interlocked.Increment(ref _droppedMessages);
            }
        }
        catch (ObjectDisposedException)
        {
            // queue closed or disposed, ignore
        }
        catch (InvalidOperationException)
        {
            // queue is closed; ignore remaining logs during shutdown.
        }
    }

    private static void WriteLine(string prefix, string message, bool force = false)
    {
        if (!_enabled && !force) return;
        string formatted = ShowTimestamp
            ? $"{prefix} {DateTime.Now:HH:mm:ss.fff} {message}"
            : $"{prefix} {message}";
        EnqueueLog(formatted, force);
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
        WriteLine($"[{GetCategory(sender)}]", message);
    }

    /// <summary>Hex dump if Logger.Enabled == true.</summary>
    public static void Hex(object? sender, string prefix, byte[] data, int length)
    {
        if (!Enabled || length <= 0 || data == null) return;
        if (length > data.Length) length = data.Length;
        // Build the full log line in memory and enqueue as a single item.
        string category = GetCategory(sender);
        string timestamp = ShowTimestamp ? $"{DateTime.Now:HH:mm:ss.fff} " : "";
        using var sw = new StringWriter();
        sw.Write($"[{category}] {timestamp}{prefix} ");
        WriteHex(sw, data, length);
        string line = sw.ToString();
        EnqueueLog(line);
    }

    /// <summary>Always log (ignores Logger.Enabled).</summary>
    public static void Always(object? sender, string message)
    {
        WriteLine($"[{GetCategory(sender)}]", message, force: true);
    }

    /// <summary>Warn log (ignores Logger.Enabled).</summary>
    public static void Warn(object? sender, string message)
    {
        WriteLine($"[{GetCategory(sender)}]", "[WARN] " + message, force: true);
    }

    /// <summary>Always hex dump (ignores Logger.Enabled).</summary>
    public static void AlwaysHex(object? sender, string prefix, byte[] data, int length)
    {
        if (length <= 0 || data == null) return;
        if (length > data.Length) length = data.Length;
        string category = GetCategory(sender);
        string timestamp = ShowTimestamp ? $"{DateTime.Now:HH:mm:ss.fff} " : "";
        using var sw = new StringWriter();
        sw.Write($"[{category}] {timestamp}{prefix} ");
        WriteHex(sw, data, length);
        string line = sw.ToString();
        EnqueueLog(line, force: true);
    }

    /// <summary>
    /// Completes the logging queue and waits for the writer task to drain.
    /// </summary>
    public static void Shutdown(int timeoutMs = 5000)
    {
        if (_shutdown) return;
        _shutdown = true;
        _logQueue.CompleteAdding();
        try
        {
            if (!_writerTask.IsCompleted)
                _writerTask.Wait(timeoutMs);
        }
        catch { /* swallow shutdown failures */ }
    }
}
