using System;
using System.Collections.Generic;
using System.Linq;

namespace CertAuditor
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (args.Length == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "/?")
            {
                PrintUsage();
                return 0;
            }

            var verb = args[0].ToLowerInvariant();
            var options = ParseOptions(args, 1);

            switch (verb)
            {
                case "capture":
                    return RunCapture(options);
                case "summarize":
                    return RunSummarize(options);
                default:
                    ConsoleHelpers.WriteError($"Unknown command '{args[0]}'. Use 'capture' or 'summarize'.");
                    PrintUsage();
                    return 1;
            }
        }

        private static int RunCapture(Dictionary<string, string> options)
        {
            // --log (required)
            if (!options.TryGetValue("--log", out var logPath) || string.IsNullOrWhiteSpace(logPath))
            {
                ConsoleHelpers.WriteError("--log is required for the capture command.");
                return 1;
            }

            // Check elevation
            if (!ConsoleHelpers.IsElevated())
            {
                ConsoleHelpers.WriteError(
                    "CertAuditor requires administrator privileges to create an ETW session. " +
                    "Please run from an elevated command prompt.");
                return 1;
            }

            // --duration (optional)
            TimeSpan? duration = null;
            if (options.TryGetValue("--duration", out var durationStr))
            {
                duration = DurationParser.TryParse(durationStr);
                if (!duration.HasValue)
                {
                    ConsoleHelpers.WriteError(
                        $"Invalid --duration value '{durationStr}'. " +
                        "Use a number followed by s, m, h, or d (e.g., 30s, 10m, 1h, 2d).");
                    return 1;
                }
            }

            // --events (optional, default: 11,30)
            var eventIds = new HashSet<int> { 11, 30 };
            if (options.TryGetValue("--events", out var eventsStr))
            {
                eventIds = ParseEventIds(eventsStr);
                if (eventIds == null)
                    return 1;
            }

            // --store (optional)
            options.TryGetValue("--store", out var storeFilter);

            // --thumbprint (optional)
            HashSet<string> thumbprints = null;
            if (options.TryGetValue("--thumbprint", out var thumbStr) && !string.IsNullOrWhiteSpace(thumbStr))
            {
                thumbprints = new HashSet<string>(
                    thumbStr.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(t => t.Trim()),
                    StringComparer.OrdinalIgnoreCase);
            }

            ConsoleHelpers.InstallCancelHandler();

            try
            {
                using (var session = new EtwCaptureSession(logPath, eventIds, storeFilter, thumbprints))
                {
                    session.Run(ConsoleHelpers.CancellationToken, duration);
                }
            }
            catch (UnauthorizedAccessException)
            {
                ConsoleHelpers.WriteError(
                    "Access denied. An ETW session with the same name may already be running " +
                    "from a previous crash. Try: logman stop CertAuditor-CAPI2 -ets");
                return 1;
            }
            catch (Exception ex)
            {
                ConsoleHelpers.WriteError($"Capture failed: {ex.Message}");
                return 1;
            }

            return 0;
        }

        private static int RunSummarize(Dictionary<string, string> options)
        {
            if (!options.TryGetValue("--log", out var logPath) || string.IsNullOrWhiteSpace(logPath))
            {
                ConsoleHelpers.WriteError("--log is required for the summarize command.");
                return 1;
            }

            options.TryGetValue("--format", out var format);
            var useCsv = string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase);

            try
            {
                var summaries = LogParser.Summarize(logPath);

                if (useCsv)
                    LogParser.WriteCsv(summaries, Console.Out);
                else
                    LogParser.WriteTable(summaries, Console.Out);
            }
            catch (Exception ex)
            {
                ConsoleHelpers.WriteError($"Summarize failed: {ex.Message}");
                return 1;
            }

            return 0;
        }

        private static HashSet<int> ParseEventIds(string input)
        {
            var result = new HashSet<int>();
            var parts = input.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var part in parts)
            {
                if (!int.TryParse(part.Trim(), out var id))
                {
                    ConsoleHelpers.WriteError($"Invalid event ID '{part.Trim()}'. Must be a number.");
                    return null;
                }

                if (!EtwCaptureSession.AllowedEventIds.ContainsKey(id))
                {
                    ConsoleHelpers.WriteError(
                        $"Event ID {id} is not a recognized CAPI2 event. " +
                        $"Allowed values: {string.Join(", ", EtwCaptureSession.AllowedEventIds.Keys.OrderBy(x => x))}");
                    return null;
                }

                result.Add(id);
            }

            if (result.Count == 0)
            {
                ConsoleHelpers.WriteError("--events requires at least one event ID.");
                return null;
            }

            return result;
        }

        private static Dictionary<string, string> ParseOptions(string[] args, int startIndex)
        {
            var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            for (int i = startIndex; i < args.Length; i++)
            {
                if (args[i].StartsWith("--"))
                {
                    var key = args[i];
                    string value = null;

                    if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                    {
                        value = args[i + 1];
                        i++;
                    }

                    options[key] = value;
                }
            }

            return options;
        }

        private static void PrintUsage()
        {
            Console.WriteLine(@"CertAuditor — Windows Certificate Usage Auditor

Usage:
  CertAuditor.exe capture --log <path> [options]
  CertAuditor.exe summarize --log <path> [--format table|csv]

Commands:
  capture     Start a real-time ETW capture session for CAPI2 certificate events.
  summarize   Parse a captured log file and display a usage summary.

Capture Options:
  --log <path>            Path to the output log file (required, append mode).
  --duration <value>      How long to capture before auto-stopping.
                          Format: <number><unit> where unit is s, m, h, or d.
                          Examples: 30s, 10m, 1h, 2d
  --store <name>          Filter to a specific certificate store.
                          Examples: ""LocalMachine\My"", ""CurrentUser\Root""
  --thumbprint <list>     Filter to specific certificate thumbprint(s).
                          Comma-separated, case-insensitive.
  --events <list>         Comma-separated list of CAPI2 event IDs to capture.
                          Default: 11,30

Summarize Options:
  --log <path>            Path to the log file to summarize (required).
  --format <type>         Output format: table (default) or csv.

Allowed Event IDs:");

            foreach (var kvp in EtwCaptureSession.AllowedEventIds.OrderBy(x => x.Key))
            {
                Console.WriteLine($"  {kvp.Key,4}  {kvp.Value}");
            }

            Console.WriteLine(@"
Requirements:
  - Windows Server 2016+ or Windows 10+ with .NET Framework 4.8
  - Administrator privileges (required to create ETW sessions)

Examples:
  CertAuditor.exe capture --log C:\logs\cert-audit.log --duration 1h
  CertAuditor.exe capture --log audit.log --store ""LocalMachine\My"" --duration 7d
  CertAuditor.exe capture --log audit.log --thumbprint AB12CD34EF --duration 2d
  CertAuditor.exe capture --log audit.log --events 11,30,41,90 --duration 1h
  CertAuditor.exe summarize --log C:\logs\cert-audit.log
  CertAuditor.exe summarize --log C:\logs\cert-audit.log --format csv");
        }
    }
}
