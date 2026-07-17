using System.Runtime.CompilerServices;
using Xunit;

// Several tests mutate process-wide static state that Logger and other
// singletons depend on — Console.Out (LoggerTests) and Logger.Enabled
// (LoggerTests), and real EIPServerTransport/CSPTransport instances started
// by other test classes log through that same static Logger internally.
// xUnit runs different test classes (collections) in parallel by default,
// so without this, a test in one class could observe (or pollute) Logger's
// global state while another class's test is mid-assertion on it.
//
// This trades a bit of wall-clock test time for eliminating that entire
// class of flaky, hard-to-reproduce cross-test interference.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace PcccGateway.Tests;

/// <summary>
/// Runs once before any test executes. Raises the ThreadPool's minimum
/// worker-thread count so tests that do Task.Run(...) + a blocking
/// wait/WaitAsync (common across the DF1/CSP/EIP transport test suites)
/// don't intermittently time out on a contended CI runner.
/// <para>
/// By default, .NET's ThreadPool only injects new worker threads at a slow,
/// throttled rate (roughly one every 0.5-1s) once it runs out of idle
/// threads. Under a burst of many blocking Task.Run calls — exactly what
/// these tests do — a freshly queued task can sit waiting for a thread for
/// a second or more on a slower/more contended machine (macOS GitHub-hosted
/// runners in particular), even though the work itself is effectively
/// instantaneous. That shows up as a flaky, seemingly-random TimeoutException
/// on whichever test's task happens to be queued at the wrong moment — not a
/// bug in the code under test.
/// </para>
/// </summary>
public static class ThreadPoolWarmup
{
    [ModuleInitializer]
    internal static void EnsureMinThreads()
    {
        // 32 is comfortably more than this suite ever needs concurrently;
        // the cost of reserving that many is negligible for a test run.
        ThreadPool.GetMinThreads(out int minWorker, out int minIocp);
        int targetWorker = Math.Max(minWorker, 32);
        int targetIocp = Math.Max(minIocp, 32);

        // Best-effort only: this exists purely to reduce CI flakiness. A module
        // initializer that throws fails the entire test assembly load, which is
        // a far worse outcome than the occasional flaky timeout this is meant to
        // prevent — so a failed SetMinThreads here is deliberately swallowed
        // rather than escalated. Worst case, tests behave as they did before
        // this fix existed.
        _ = ThreadPool.SetMinThreads(targetWorker, targetIocp);
    }
}
