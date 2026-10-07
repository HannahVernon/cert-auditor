using System;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace CertAuditor.Tests
{
    public class SeenCertificateReportTests
    {
        [Fact]
        public void WriteTable_EmptyList_WritesNoDataMessage()
        {
            var writer = new StringWriter();

            SeenCertificateReport.WriteTable(new List<SeenCertificate>(), null, writer);

            Assert.Contains("No certificates were observed", writer.ToString());
        }

        [Fact]
        public void WriteTable_IncludesThumbprintSubjectDatesAndCount()
        {
            var certs = new List<SeenCertificate>
            {
                new SeenCertificate { Thumbprint = "AAAA", Subject = "CN=Test1", Count = 3 },
            };
            var notBefore = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var notAfter = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var writer = new StringWriter();

            SeenCertificateReport.WriteTable(certs, null, writer, (thumb, hint) => (notBefore, notAfter));

            var output = writer.ToString();
            Assert.Contains("AAAA", output);
            Assert.Contains("CN=Test1", output);
            Assert.Contains("2025-01-01 00:00:00", output);
            Assert.Contains("2026-01-01 00:00:00", output);
            Assert.Contains("3", output);
        }

        [Fact]
        public void WriteTable_UnresolvableValidity_ShowsNotAvailable()
        {
            var certs = new List<SeenCertificate>
            {
                new SeenCertificate { Thumbprint = "BBBB", Subject = "CN=Test2", Count = 1 },
            };
            var writer = new StringWriter();

            SeenCertificateReport.WriteTable(certs, null, writer, (thumb, hint) => null);

            Assert.Contains("N/A", writer.ToString());
        }

        [Fact]
        public void WriteTable_OrdersByCountDescending()
        {
            var certs = new List<SeenCertificate>
            {
                new SeenCertificate { Thumbprint = "LOWCOUNT", Subject = "CN=Low", Count = 1 },
                new SeenCertificate { Thumbprint = "HIGHCOUNT", Subject = "CN=High", Count = 10 },
            };
            var writer = new StringWriter();

            SeenCertificateReport.WriteTable(certs, null, writer, (thumb, hint) => null);

            var output = writer.ToString();
            Assert.True(output.IndexOf("HIGHCOUNT", StringComparison.Ordinal)
                < output.IndexOf("LOWCOUNT", StringComparison.Ordinal));
        }

        [Fact]
        public void WriteTable_PassesStoreHintThroughToLookup()
        {
            var certs = new List<SeenCertificate>
            {
                new SeenCertificate { Thumbprint = "AAAA", Subject = "CN=Test1", Count = 1 },
            };
            string capturedHint = null;
            var writer = new StringWriter();

            SeenCertificateReport.WriteTable(certs, @"LocalMachine\My", writer, (thumb, hint) =>
            {
                capturedHint = hint;
                return null;
            });

            Assert.Equal(@"LocalMachine\My", capturedHint);
        }
    }
}
