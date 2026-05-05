using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace CertAuditor
{
    /// <summary>
    /// Parses a CertAuditor log file and produces a summary of certificate usage.
    /// </summary>
    public static class LogParser
    {
        /// <summary>
        /// Summary record for a single certificate.
        /// </summary>
        public class CertSummary
        {
            public string Thumbprint { get; set; }
            public string Subject { get; set; }
            public string Issuer { get; set; }
            public int Count { get; set; }
            public DateTimeOffset FirstSeen { get; set; }
            public DateTimeOffset LastSeen { get; set; }
            public HashSet<string> Processes { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            public HashSet<int> EventIds { get; set; } = new HashSet<int>();
        }

        /// <summary>
        /// Reads a log file and aggregates events by certificate thumbprint.
        /// </summary>
        public static List<CertSummary> Summarize(string logFilePath)
        {
            if (!File.Exists(logFilePath))
                throw new FileNotFoundException($"Log file not found: {logFilePath}");

            var summaries = new Dictionary<string, CertSummary>(StringComparer.OrdinalIgnoreCase);
            int lineNumber = 0;
            int parseErrors = 0;

            using (var reader = new StreamReader(logFilePath, System.Text.Encoding.UTF8))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    lineNumber++;

                    // Skip header line(s)
                    if (line.StartsWith("Timestamp", StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (string.IsNullOrWhiteSpace(line))
                        continue;

                    var evt = CertUsageEvent.Parse(line);
                    if (evt == null)
                    {
                        parseErrors++;
                        continue;
                    }

                    // Skip events with no thumbprint — can't aggregate without an identifier
                    if (string.IsNullOrEmpty(evt.Thumbprint))
                        continue;

                    if (!summaries.TryGetValue(evt.Thumbprint, out var summary))
                    {
                        summary = new CertSummary
                        {
                            Thumbprint = evt.Thumbprint,
                            Subject = evt.Subject,
                            Issuer = evt.Issuer,
                            FirstSeen = evt.Timestamp,
                            LastSeen = evt.Timestamp,
                            Count = 0
                        };
                        summaries[evt.Thumbprint] = summary;
                    }

                    summary.Count++;

                    if (evt.Timestamp < summary.FirstSeen)
                        summary.FirstSeen = evt.Timestamp;
                    if (evt.Timestamp > summary.LastSeen)
                        summary.LastSeen = evt.Timestamp;

                    if (!string.IsNullOrEmpty(evt.ProcessName))
                        summary.Processes.Add(evt.ProcessName);

                    summary.EventIds.Add(evt.EventId);

                    // Use the most recent non-empty subject/issuer
                    if (!string.IsNullOrEmpty(evt.Subject))
                        summary.Subject = evt.Subject;
                    if (!string.IsNullOrEmpty(evt.Issuer))
                        summary.Issuer = evt.Issuer;
                }
            }

            if (parseErrors > 0)
            {
                ConsoleHelpers.WriteInfo(
                    $"Warning: {parseErrors} line(s) could not be parsed and were skipped.");
            }

            return summaries.Values
                .OrderByDescending(s => s.Count)
                .ToList();
        }

        /// <summary>
        /// Formats summaries as an aligned console table.
        /// </summary>
        public static void WriteTable(List<CertSummary> summaries, TextWriter output)
        {
            if (summaries.Count == 0)
            {
                output.WriteLine("No certificate usage events found in the log file.");
                return;
            }

            // Column widths
            const int thumbWidth = 44;
            const int subjectWidth = 40;
            const int countWidth = 7;
            const int firstWidth = 20;
            const int lastWidth = 20;
            const int processWidth = 40;

            output.WriteLine(
                $"{"Thumbprint".PadRight(thumbWidth)} " +
                $"{"Subject".PadRight(subjectWidth)} " +
                $"{"Count".PadLeft(countWidth)} " +
                $"{"First Seen".PadRight(firstWidth)} " +
                $"{"Last Seen".PadRight(lastWidth)} " +
                $"{"Processes".PadRight(processWidth)}");

            output.WriteLine(new string('-', thumbWidth + subjectWidth + countWidth + firstWidth + lastWidth + processWidth + 5));

            foreach (var s in summaries)
            {
                var thumb = Truncate(s.Thumbprint, thumbWidth);
                var subject = Truncate(s.Subject, subjectWidth);
                var processes = Truncate(string.Join(", ", s.Processes), processWidth);

                output.WriteLine(
                    $"{thumb.PadRight(thumbWidth)} " +
                    $"{subject.PadRight(subjectWidth)} " +
                    $"{s.Count.ToString(CultureInfo.InvariantCulture).PadLeft(countWidth)} " +
                    $"{FormatTimestamp(s.FirstSeen).PadRight(firstWidth)} " +
                    $"{FormatTimestamp(s.LastSeen).PadRight(lastWidth)} " +
                    $"{processes}");
            }

            output.WriteLine();
            output.WriteLine($"Total: {summaries.Count} unique certificate(s), " +
                             $"{summaries.Sum(s => s.Count)} event(s).");
        }

        /// <summary>
        /// Formats summaries as CSV (tab-delimited).
        /// </summary>
        public static void WriteCsv(List<CertSummary> summaries, TextWriter output)
        {
            output.WriteLine("Thumbprint\tSubject\tIssuer\tCount\tFirstSeen\tLastSeen\tProcesses\tEventIds");

            foreach (var s in summaries)
            {
                output.WriteLine(string.Join("\t",
                    s.Thumbprint,
                    s.Subject,
                    s.Issuer,
                    s.Count.ToString(CultureInfo.InvariantCulture),
                    s.FirstSeen.ToString("o", CultureInfo.InvariantCulture),
                    s.LastSeen.ToString("o", CultureInfo.InvariantCulture),
                    string.Join(", ", s.Processes),
                    string.Join(", ", s.EventIds.OrderBy(x => x))));
            }
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;
            return value.Length <= maxLength ? value : value.Substring(0, maxLength - 3) + "...";
        }

        private static string FormatTimestamp(DateTimeOffset ts)
        {
            return ts.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        }
    }
}
