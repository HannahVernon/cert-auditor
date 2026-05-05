using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace CertAuditor.Tests
{
    public class LogParserTests
    {
        [Fact]
        public void Summarize_EmptyFile_ReturnsEmptyList()
        {
            var path = CreateTempLog(CertUsageEvent.HeaderLine);

            try
            {
                var result = LogParser.Summarize(path);

                Assert.Empty(result);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void Summarize_MissingFile_ThrowsFileNotFoundException()
        {
            Assert.Throws<FileNotFoundException>(
                () => LogParser.Summarize(@"C:\nonexistent\path\fake.log"));
        }

        [Fact]
        public void Summarize_AggregatesByThumbprint()
        {
            var lines = new[]
            {
                CertUsageEvent.HeaderLine,
                MakeLogLine("AAAA", "CN=Cert1", "CN=Issuer1", 11, "svc1.exe"),
                MakeLogLine("AAAA", "CN=Cert1", "CN=Issuer1", 30, "svc1.exe"),
                MakeLogLine("BBBB", "CN=Cert2", "CN=Issuer2", 11, "svc2.exe"),
            };
            var path = CreateTempLog(string.Join(Environment.NewLine, lines));

            try
            {
                var result = LogParser.Summarize(path);

                Assert.Equal(2, result.Count);

                var certA = result.First(s => s.Thumbprint == "AAAA");
                Assert.Equal(2, certA.Count);
                Assert.Contains(11, certA.EventIds);
                Assert.Contains(30, certA.EventIds);

                var certB = result.First(s => s.Thumbprint == "BBBB");
                Assert.Equal(1, certB.Count);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void Summarize_TracksProcessNames()
        {
            var lines = new[]
            {
                CertUsageEvent.HeaderLine,
                MakeLogLine("AAAA", "CN=Cert1", "CN=Issuer1", 11, "svc1.exe"),
                MakeLogLine("AAAA", "CN=Cert1", "CN=Issuer1", 11, "svc2.exe"),
                MakeLogLine("AAAA", "CN=Cert1", "CN=Issuer1", 11, "svc1.exe"),
            };
            var path = CreateTempLog(string.Join(Environment.NewLine, lines));

            try
            {
                var result = LogParser.Summarize(path);

                Assert.Single(result);
                Assert.Equal(3, result[0].Count);
                Assert.Equal(2, result[0].Processes.Count);
                Assert.Contains("svc1.exe", result[0].Processes);
                Assert.Contains("svc2.exe", result[0].Processes);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void Summarize_OrdersByCountDescending()
        {
            var lines = new List<string> { CertUsageEvent.HeaderLine };

            // BBBB gets 3 events, AAAA gets 1
            lines.Add(MakeLogLine("AAAA", "CN=Cert1", "", 11, "test.exe"));
            lines.Add(MakeLogLine("BBBB", "CN=Cert2", "", 11, "test.exe"));
            lines.Add(MakeLogLine("BBBB", "CN=Cert2", "", 30, "test.exe"));
            lines.Add(MakeLogLine("BBBB", "CN=Cert2", "", 11, "test.exe"));

            var path = CreateTempLog(string.Join(Environment.NewLine, lines));

            try
            {
                var result = LogParser.Summarize(path);

                Assert.Equal("BBBB", result[0].Thumbprint);
                Assert.Equal("AAAA", result[1].Thumbprint);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void Summarize_SkipsEventsWithNoThumbprint()
        {
            var lines = new[]
            {
                CertUsageEvent.HeaderLine,
                MakeLogLine("", "CN=NoThumb", "", 11, "test.exe"),
                MakeLogLine("AAAA", "CN=HasThumb", "", 11, "test.exe"),
            };
            var path = CreateTempLog(string.Join(Environment.NewLine, lines));

            try
            {
                var result = LogParser.Summarize(path);

                Assert.Single(result);
                Assert.Equal("AAAA", result[0].Thumbprint);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void Summarize_SkipsMalformedLines()
        {
            var lines = new[]
            {
                CertUsageEvent.HeaderLine,
                "this is not a valid log line",
                MakeLogLine("AAAA", "CN=Valid", "", 11, "test.exe"),
                "also garbage",
            };
            var path = CreateTempLog(string.Join(Environment.NewLine, lines));

            try
            {
                var result = LogParser.Summarize(path);

                Assert.Single(result);
                Assert.Equal("AAAA", result[0].Thumbprint);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void Summarize_TracksFirstAndLastSeen()
        {
            var ts1 = new DateTimeOffset(2026, 1, 1, 10, 0, 0, TimeSpan.Zero);
            var ts2 = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
            var ts3 = new DateTimeOffset(2026, 1, 1, 8, 0, 0, TimeSpan.Zero);

            var lines = new[]
            {
                CertUsageEvent.HeaderLine,
                MakeLogLine("AAAA", "CN=Test", "", 11, "test.exe", ts1),
                MakeLogLine("AAAA", "CN=Test", "", 11, "test.exe", ts2),
                MakeLogLine("AAAA", "CN=Test", "", 11, "test.exe", ts3),
            };
            var path = CreateTempLog(string.Join(Environment.NewLine, lines));

            try
            {
                var result = LogParser.Summarize(path);

                Assert.Single(result);
                Assert.Equal(ts3, result[0].FirstSeen);
                Assert.Equal(ts2, result[0].LastSeen);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void WriteTable_EmptyList_WritesNoDataMessage()
        {
            var writer = new StringWriter();

            LogParser.WriteTable(new List<LogParser.CertSummary>(), writer);

            Assert.Contains("No certificate usage events", writer.ToString());
        }

        [Fact]
        public void WriteCsv_ProducesHeaderAndRows()
        {
            var summaries = new List<LogParser.CertSummary>
            {
                new LogParser.CertSummary
                {
                    Thumbprint = "AAAA",
                    Subject = "CN=Test",
                    Issuer = "CN=Issuer",
                    Count = 5,
                    FirstSeen = DateTimeOffset.UtcNow,
                    LastSeen = DateTimeOffset.UtcNow,
                    Processes = new System.Collections.Generic.HashSet<string> { "svc.exe" },
                    EventIds = new System.Collections.Generic.HashSet<int> { 11, 30 }
                }
            };
            var writer = new StringWriter();

            LogParser.WriteCsv(summaries, writer);

            var output = writer.ToString();
            Assert.Contains("Thumbprint\t", output);
            Assert.Contains("AAAA", output);
            Assert.Contains("CN=Test", output);
            Assert.Contains("svc.exe", output);
        }

        private static string MakeLogLine(string thumbprint, string subject, string issuer,
            int eventId, string processName, DateTimeOffset? timestamp = null)
        {
            var ts = timestamp ?? DateTimeOffset.UtcNow;
            var evt = new CertUsageEvent
            {
                Timestamp = ts,
                EventId = eventId,
                Thumbprint = thumbprint,
                Subject = subject,
                Issuer = issuer,
                StoreName = "",
                ProcessId = 1234,
                ProcessName = processName,
                Result = 0
            };
            return evt.ToLogLine();
        }

        private static string CreateTempLog(string content)
        {
            var path = Path.Combine(Path.GetTempPath(),
                $"certauditor-test-{Guid.NewGuid():N}.log");
            File.WriteAllText(path, content);
            return path;
        }
    }
}
