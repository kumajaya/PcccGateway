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
