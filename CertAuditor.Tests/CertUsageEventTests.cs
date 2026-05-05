using System;
using System.Globalization;
using Xunit;

namespace CertAuditor.Tests
{
    public class CertUsageEventTests
    {
        [Fact]
        public void ToLogLine_ProducesTabDelimitedOutput()
        {
            var evt = CreateSampleEvent();

            var line = evt.ToLogLine();
            var parts = line.Split('\t');

            Assert.Equal(9, parts.Length);
        }

        [Fact]
        public void RoundTrip_PreservesAllFields()
        {
            var original = CreateSampleEvent();

            var line = original.ToLogLine();
            var parsed = CertUsageEvent.Parse(line);

            Assert.NotNull(parsed);
            Assert.Equal(original.EventId, parsed.EventId);
            Assert.Equal(original.Thumbprint, parsed.Thumbprint);
            Assert.Equal(original.Subject, parsed.Subject);
            Assert.Equal(original.Issuer, parsed.Issuer);
            Assert.Equal(original.StoreName, parsed.StoreName);
            Assert.Equal(original.ProcessId, parsed.ProcessId);
            Assert.Equal(original.ProcessName, parsed.ProcessName);
            Assert.Equal(original.Result, parsed.Result);
        }

        [Fact]
        public void RoundTrip_PreservesTimestamp()
        {
            var original = CreateSampleEvent();
            original.Timestamp = new DateTimeOffset(2026, 5, 5, 10, 30, 0, TimeSpan.FromHours(-5));

            var line = original.ToLogLine();
            var parsed = CertUsageEvent.Parse(line);

            Assert.NotNull(parsed);
            Assert.Equal(original.Timestamp, parsed.Timestamp);
        }

        [Fact]
        public void SanitizeField_RemovesTabs()
        {
            var evt = new CertUsageEvent
            {
                Timestamp = DateTimeOffset.UtcNow,
                EventId = 11,
                Thumbprint = "ABCD",
                Subject = "CN=test\twith\ttabs",
                Issuer = "CN=issuer",
                StoreName = "",
                ProcessId = 1,
                ProcessName = "test.exe",
                Result = 0
            };

            var line = evt.ToLogLine();

            // Should have exactly 8 tabs (9 fields)
            var tabCount = 0;
            foreach (var c in line)
                if (c == '\t') tabCount++;

            Assert.Equal(8, tabCount);
        }

        [Fact]
        public void SanitizeField_RemovesNewlines()
        {
            var evt = new CertUsageEvent
            {
                Timestamp = DateTimeOffset.UtcNow,
                EventId = 30,
                Thumbprint = "ABCD",
                Subject = "CN=test\r\nwith\nnewlines",
                Issuer = "",
                StoreName = "",
                ProcessId = 1,
                ProcessName = "test.exe",
                Result = 0
            };

            var line = evt.ToLogLine();

            Assert.DoesNotContain("\r", line);
            Assert.DoesNotContain("\n", line);
        }

        [Fact]
        public void Parse_NullOrEmpty_ReturnsNull()
        {
            Assert.Null(CertUsageEvent.Parse(null));
            Assert.Null(CertUsageEvent.Parse(""));
        }

        [Fact]
        public void Parse_TooFewFields_ReturnsNull()
        {
            Assert.Null(CertUsageEvent.Parse("one\ttwo\tthree"));
        }

        [Fact]
        public void Parse_InvalidTimestamp_ReturnsNull()
        {
            Assert.Null(CertUsageEvent.Parse(
                "not-a-date\t11\tABCD\tSubject\tIssuer\tStore\t1234\ttest.exe\t0"));
        }

        [Fact]
        public void Parse_InvalidEventId_ReturnsNull()
        {
            Assert.Null(CertUsageEvent.Parse(
                "2026-05-05T10:00:00Z\tNaN\tABCD\tSubject\tIssuer\tStore\t1234\ttest.exe\t0"));
        }

        [Fact]
        public void Parse_InvalidProcessId_ReturnsNull()
        {
            Assert.Null(CertUsageEvent.Parse(
                "2026-05-05T10:00:00Z\t11\tABCD\tSubject\tIssuer\tStore\tNaN\ttest.exe\t0"));
        }

        [Fact]
        public void Parse_EmptyOptionalFields_Succeeds()
        {
            var line = "2026-05-05T10:00:00.0000000+00:00\t11\t\t\t\t\t1234\t\t0";
            var parsed = CertUsageEvent.Parse(line);

            Assert.NotNull(parsed);
            Assert.Equal("", parsed.Thumbprint);
            Assert.Equal("", parsed.Subject);
            Assert.Equal("", parsed.Issuer);
            Assert.Equal("", parsed.StoreName);
            Assert.Equal("", parsed.ProcessName);
        }

        [Fact]
        public void HeaderLine_ContainsAllFieldNames()
        {
            var header = CertUsageEvent.HeaderLine;

            Assert.Contains("Timestamp", header);
            Assert.Contains("EventId", header);
            Assert.Contains("Thumbprint", header);
            Assert.Contains("Subject", header);
            Assert.Contains("Issuer", header);
            Assert.Contains("StoreName", header);
            Assert.Contains("ProcessId", header);
            Assert.Contains("ProcessName", header);
            Assert.Contains("Result", header);
        }

        private static CertUsageEvent CreateSampleEvent()
        {
            return new CertUsageEvent
            {
                Timestamp = DateTimeOffset.UtcNow,
                EventId = 11,
                Thumbprint = "860AB2B78578D8EF61F692CF81AE4B1198CCBC94",
                Subject = "CN=*.example.com",
                Issuer = "CN=Example Root CA",
                StoreName = @"LocalMachine\My",
                ProcessId = 4052,
                ProcessName = "MsSense.exe",
                Result = 0
            };
        }
    }
}
