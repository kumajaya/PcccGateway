using System;
using System.IO;
using System.Text;
using System.Threading;
using PcccGateway.Common;
using Xunit;

namespace PcccGateway.Tests;

public class LoggerTests
{
    /// <summary>
    /// Gives the background logger writer thread a moment to process
    /// the queue and write to Console.Out without terminating the thread.
    /// </summary>
    private static void WaitForLoggerFlush()
    {
        // 250 ms is more than enough for the background thread to
        // process any queued messages under normal conditions.
        Thread.Sleep(250);
    }

    [Fact]
    public void ForcedLogging_DoesNotBlockIndefinitely_WhenQueueSaturated()
    {
        var writeBlocked = new ManualResetEventSlim(false);
        var writeRelease = new ManualResetEventSlim(false);
        var originalOut = Console.Out;
        Console.SetOut(new BlockingTextWriter(writeBlocked, writeRelease));

        try
        {
            int initialDrops = Logger.DroppedMessages;

            // Fill the queue until the first log is blocked in the writer thread.
            Logger.Always(null, "start");
            Assert.True(writeBlocked.Wait(2000), "Expected logger writer thread to start writing.");

            int attempts = 0;
            while (attempts < 5000)
            {
                Logger.Info(null, $"payload {attempts}");
                if (Logger.DroppedMessages > initialDrops)
                    break;
                attempts++;
            }

            var stopWatch = System.Diagnostics.Stopwatch.StartNew();
            Logger.Always(null, "forced");
            stopWatch.Stop();

            Assert.InRange(stopWatch.ElapsedMilliseconds, 0, 500);
            Assert.True(Logger.DroppedMessages > initialDrops, "Expected at least one dropped message due to queue saturation.");
        }
        finally
        {
            writeRelease.Set();
            Console.SetOut(originalOut);
            // Wait for the blocked writer to finish so it doesn't interfere with subsequent tests.
            WaitForLoggerFlush();
        }
    }

    [Fact]
    public void Info_IsSuppressedWhenEnabledIsFalse()
    {
        var sw = new StringWriter();
        var originalOut = Console.Out;
        Console.SetOut(sw);

        try
        {
            Logger.Enabled = false;
            Logger.Info(null, "should not appear");

            WaitForLoggerFlush();

            var output = sw.ToString();
            Assert.DoesNotContain("should not appear", output);
        }
        finally
        {
            Logger.Enabled = true;
            Console.SetOut(originalOut);
        }
    }

    [Fact]
    public void Always_AndWarn_IgnoreEnabledFlag()
    {
        var sw = new StringWriter();
        var originalOut = Console.Out;
        Console.SetOut(sw);

        try
        {
            Logger.Enabled = false;
            Logger.Always(null, "always message");
            Logger.Warn(null, "warn message");

            WaitForLoggerFlush();

            var output = sw.ToString();
            Assert.Contains("always message", output);
            Assert.Contains("[WARN] warn message", output);
        }
        finally
        {
            Logger.Enabled = true;
            Console.SetOut(originalOut);
        }
    }

    private sealed class BlockingTextWriter : TextWriter
    {
        private readonly ManualResetEventSlim _writeStarted;
        private readonly ManualResetEventSlim _writeRelease;

        public BlockingTextWriter(ManualResetEventSlim writeStarted, ManualResetEventSlim writeRelease)
        {
            _writeStarted = writeStarted;
            _writeRelease = writeRelease;
        }

        public override Encoding Encoding => Encoding.UTF8;

        public override void WriteLine(string? value)
        {
            _writeStarted.Set();
            _writeRelease.Wait();
        }
    }
}
