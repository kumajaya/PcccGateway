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
using System.Text;
using PcccGateway.Client;
using PcccGateway.Server;

namespace PcccGateway.Common;

/// <summary>
/// Centralized logging for the PCCC emulator.
/// - Info/Hex respect Logger.Enabled (global switch).
/// - Always/AlwaysHex always write (useful for startup/shutdown/fatal errors).
/// - Category is auto-detected from sender type.
/// - Thread-safe and non-blocking: callers only enqueue log messages; a dedicated
///   background task writes them to the console, ensuring ordering and minimal impact.
/// - Console output encoding is automatically set to UTF-8 for correct Unicode display.
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
        // Ensure console output uses UTF-8 so that all Unicode characters
        // (product names, symbols, etc.) display correctly.
        // This is a best-effort attempt; the user can override by setting
        // Console.OutputEncoding earlier in Program.Main().
        try
        {
            Console.OutputEncoding = Encoding.UTF8;
        }
        catch
        {
            // Ignore – fall back to default encoding.
        }

        // Start a dedicated background thread to write logs.
        _writerTask = Task.Factory.StartNew(() =>
        {
            foreach (var message in _logQueue.GetConsumingEnumerable())
            {
                try
                {
                    Console.WriteLine(message);
                    // Flush immediately to guarantee that the text is written
                    // to the underlying stream (console or redirected output)
                    // without buffering delays. This prevents partial output
                    // when the process terminates abruptly.
                    Console.Out.Flush();
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

    /// <summary>
    /// Enables or disables logging for Info/Hex calls.
    /// Always/AlwaysHex/Warn ignore this setting.
    /// </summary>
    public static bool Enabled
    {
        get => _enabled;
        set => _enabled = value;
    }

    /// <summary>
    /// Writes a hex dump of <paramref name="data"/> (up to <paramref name="length"/> bytes)
    /// to the specified <paramref name="writer"/>.
    /// </summary>
    private static void WriteHex(TextWriter writer, byte[] data, int length)
    {
        for (int i = 0; i < length; i++)
        {
            if (i > 0) writer.Write(' ');
            writer.Write(data[i].ToString("X2"));
        }
    }

    /// <summary>
    /// Number of log messages that were dropped because the queue was full.
    /// </summary>
    public static int DroppedMessages => Volatile.Read(ref _droppedMessages);

    /// <summary>
    /// Enqueues a log line.
    /// If <paramref name="force"/> is true, the method makes a best-effort
    /// attempt to add the line to the queue, bypassing <see cref="Logger.Enabled"/>.
    /// It may still be dropped if the queue is full or if shutdown is in progress.
    /// </summary>
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

    /// <summary>
    /// Formats a log line with optional timestamp and enqueues it.
    /// If <paramref name="force"/> is true, the line bypasses
    /// <see cref="Logger.Enabled"/>, but it is still only best-effort:
    /// the message may be dropped when the queue is full or during shutdown.
    /// </summary>
    private static void WriteLine(string prefix, string message, bool force = false)
    {
        if (!_enabled && !force) return;
        string formatted = ShowTimestamp
            ? $"{prefix} {DateTime.Now:HH:mm:ss.fff} {message}"
            : $"{prefix} {message}";
        EnqueueLog(formatted, force);
    }

    /// <summary>
    /// Returns a short category string for the given sender object.
    /// The category is used as a tag in log output.
    /// </summary>
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

    /// <summary>
    /// Logs an informational message. Respects Logger.Enabled.
    /// </summary>
    public static void Info(object? sender, string message)
    {
        if (!Enabled) return;
        WriteLine($"[{GetCategory(sender)}]", message);
    }

    /// <summary>
    /// Logs a hex dump. Respects Logger.Enabled.
    /// </summary>
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

    /// <summary>
    /// Logs an important message that is always written (ignores Logger.Enabled).
    /// </summary>
    public static void Always(object? sender, string message)
    {
        WriteLine($"[{GetCategory(sender)}]", message, force: true);
    }

    /// <summary>
    /// Logs a warning message that is always written (ignores Logger.Enabled).
    /// </summary>
    public static void Warn(object? sender, string message)
    {
        WriteLine($"[{GetCategory(sender)}]", "[WARN] " + message, force: true);
    }

    /// <summary>
    /// Logs a hex dump that is always written (ignores Logger.Enabled).
    /// </summary>
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
    /// Gracefully shuts down the logger:
    /// - Completes the queue (no more messages will be accepted).
    /// - Waits for the background writer task to drain all queued messages.
    /// - If the timeout expires, remaining messages may be lost.
    /// </summary>
    /// <param name="timeoutMs">Maximum time to wait for the writer to finish (default 5000 ms).</param>
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
        catch
        {
            // Swallow shutdown failures – we are exiting anyway.
        }
    }
}
