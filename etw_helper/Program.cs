// NetGuardEtwHelper
// Consumes the Windows kernel network ETW provider and writes real per-process
// byte counts (TCP + UDP, send + receive) to a JSON file once per second.
//
// This runs as a SEPARATE elevated process from the Python backend. If anything
// goes wrong here it cannot crash NetGuard — the backend just stops seeing fresh
// data and falls back to estimation mode.
//
// Usage:  NetGuardEtwHelper.exe <output-json-path>
// Output: {"ts": <unix-ms>, "procs": {"<pid>": [sentBytes, recvBytes], ...}}
//         (byte counts are cumulative since this helper started; the reader diffs)

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;

internal static class Program
{
    private const string SessionName = "NetGuardKernelNet";

    // pid -> [sentBytes, recvBytes], cumulative since start.
    private static readonly ConcurrentDictionary<int, long[]> Counters = new();

    private static void Add(int pid, int size, int direction)
    {
        if (pid <= 0 || size <= 0) return;
        long[] acc = Counters.GetOrAdd(pid, _ => new long[2]);
        Interlocked.Add(ref acc[direction], size);
    }

    private static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("usage: NetGuardEtwHelper <output-json-path>");
            return 2;
        }
        string outPath = args[0];

        if (TraceEventSession.IsElevated() != true)
        {
            Console.Error.WriteLine("NOT_ELEVATED");
            return 5;
        }

        // Background writer: snapshot the counters to disk once per second.
        var stopWriter = new ManualResetEventSlim(false);
        var writer = new Thread(() =>
        {
            while (!stopWriter.IsSet)
            {
                WriteSnapshot(outPath);
                stopWriter.Wait(1000);
            }
            WriteSnapshot(outPath);
        }) { IsBackground = true };
        writer.Start();

        try
        {
            using var session = new TraceEventSession(SessionName) { StopOnDispose = true };
            session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

            var k = session.Source.Kernel;
            // TCP (IPv4 + IPv6)
            k.TcpIpSend       += d => Add(d.ProcessID, d.size, 0);
            k.TcpIpRecv       += d => Add(d.ProcessID, d.size, 1);
            k.TcpIpSendIPV6   += d => Add(d.ProcessID, d.size, 0);
            k.TcpIpRecvIPV6   += d => Add(d.ProcessID, d.size, 1);
            // UDP / QUIC (IPv4 + IPv6)
            k.UdpIpSend       += d => Add(d.ProcessID, d.size, 0);
            k.UdpIpRecv       += d => Add(d.ProcessID, d.size, 1);
            k.UdpIpSendIPV6   += d => Add(d.ProcessID, d.size, 0);
            k.UdpIpRecvIPV6   += d => Add(d.ProcessID, d.size, 1);

            // Stop cleanly if the parent closes our stdin (it redirects it).
            var stdinWatch = new Thread(() =>
            {
                try { Console.In.ReadToEnd(); } catch { }
                try { session.Source.StopProcessing(); } catch { }
            }) { IsBackground = true };
            stdinWatch.Start();

            session.Source.Process(); // blocks until stopped
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("ETW_ERROR: " + ex.Message);
            stopWriter.Set();
            return 1;
        }

        stopWriter.Set();
        return 0;
    }

    private static void WriteSnapshot(string outPath)
    {
        var sb = new StringBuilder(1024);
        sb.Append("{\"ts\":").Append(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()).Append(",\"procs\":{");
        bool first = true;
        foreach (var kv in Counters)
        {
            if (!first) sb.Append(',');
            first = false;
            sb.Append('"').Append(kv.Key).Append("\":[")
              .Append(Interlocked.Read(ref kv.Value[0])).Append(',')
              .Append(Interlocked.Read(ref kv.Value[1])).Append(']');
        }
        sb.Append("}}");

        try
        {
            string tmp = outPath + ".tmp";
            File.WriteAllText(tmp, sb.ToString());
            File.Copy(tmp, outPath, true);
        }
        catch { /* reader may be mid-read; try again next tick */ }
    }
}
