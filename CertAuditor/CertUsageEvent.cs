using System;
using System.Globalization;

namespace CertAuditor
{
    /// <summary>
    /// Represents a single certificate-usage event captured from the CAPI2 ETW provider.
    /// </summary>
    public class CertUsageEvent
    {
        public DateTimeOffset Timestamp { get; set; }
        public int EventId { get; set; }
        public string Thumbprint { get; set; }
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public string StoreName { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public int Result { get; set; }

        private const string TimestampFormat = "o";
        private const char Delimiter = '\t';

        public static readonly string HeaderLine = string.Join(
            Delimiter.ToString(),
            "Timestamp", "EventId", "Thumbprint", "Subject", "Issuer",
            "StoreName", "ProcessId", "ProcessName", "Result");

        public string ToLogLine()
        {
            return string.Join(
                Delimiter.ToString(),
                Timestamp.ToString(TimestampFormat, CultureInfo.InvariantCulture),
                EventId.ToString(CultureInfo.InvariantCulture),
                SanitizeField(Thumbprint),
                SanitizeField(Subject),
                SanitizeField(Issuer),
                SanitizeField(StoreName),
                ProcessId.ToString(CultureInfo.InvariantCulture),
                SanitizeField(ProcessName),
                Result.ToString(CultureInfo.InvariantCulture));
        }

        public static CertUsageEvent Parse(string line)
        {
            if (string.IsNullOrEmpty(line))
                return null;

            var parts = line.Split(Delimiter);
            if (parts.Length < 9)
                return null;

            var evt = new CertUsageEvent();

            if (!DateTimeOffset.TryParse(parts[0], CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out var ts))
                return null;

            evt.Timestamp = ts;

            if (!int.TryParse(parts[1], NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out var eventId))
                return null;

            evt.EventId = eventId;
            evt.Thumbprint = parts[2];
            evt.Subject = parts[3];
            evt.Issuer = parts[4];
            evt.StoreName = parts[5];

            if (!int.TryParse(parts[6], NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out var pid))
                return null;

            evt.ProcessId = pid;
            evt.ProcessName = parts[7];

            if (!int.TryParse(parts[8], NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out var result))
                return null;

            evt.Result = result;

            return evt;
        }

        /// <summary>
        /// Replaces tabs and newlines in field values to prevent log corruption.
        /// </summary>
        private static string SanitizeField(string value)
        {
            if (string.IsNullOrEmpty(value))
                return string.Empty;

            return value
                .Replace('\t', ' ')
                .Replace('\r', ' ')
                .Replace('\n', ' ');
        }
    }
}
