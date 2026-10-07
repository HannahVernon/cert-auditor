using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace CertAuditor
{
    /// <summary>
    /// Prints the end-of-run summary of certificates seen during a capture
    /// session: thumbprint, subject, validity period, and how many matching
    /// events were observed for each.
    /// </summary>
    public static class SeenCertificateReport
    {
        /// <summary>
        /// Delegate signature for looking up a certificate's validity period
        /// by thumbprint. Defaults to <see cref="CertificateStoreLookup.TryGetValidity"/>;
        /// overridable for testing.
        /// </summary>
        public delegate (DateTime NotBefore, DateTime NotAfter)? ValidityLookup(string thumbprint, string storeHint);

        public static void WriteTable(
            IEnumerable<SeenCertificate> certificates,
            string storeHint,
            TextWriter output,
            ValidityLookup lookup = null)
        {
            lookup = lookup ?? CertificateStoreLookup.TryGetValidity;

            var ordered = certificates
                .OrderByDescending(c => c.Count)
                .ToList();

            if (ordered.Count == 0)
            {
                output.WriteLine("No certificates were observed during this capture.");
                return;
            }

            const int thumbWidth = 44;
            const int subjectWidth = 40;
            const int validFromWidth = 20;
            const int validToWidth = 20;
            const int countWidth = 7;

            output.WriteLine(
                $"{"Thumbprint".PadRight(thumbWidth)} " +
                $"{"Subject".PadRight(subjectWidth)} " +
                $"{"Valid From".PadRight(validFromWidth)} " +
                $"{"Valid To".PadRight(validToWidth)} " +
                $"{"Count".PadLeft(countWidth)}");

            output.WriteLine(new string('-', thumbWidth + subjectWidth + validFromWidth + validToWidth + countWidth + 4));

            foreach (var cert in ordered)
            {
                var validity = lookup(cert.Thumbprint, storeHint);
                var validFrom = validity.HasValue ? FormatTimestamp(validity.Value.NotBefore) : "N/A";
                var validTo = validity.HasValue ? FormatTimestamp(validity.Value.NotAfter) : "N/A";

                output.WriteLine(
                    $"{Truncate(cert.Thumbprint, thumbWidth).PadRight(thumbWidth)} " +
                    $"{Truncate(cert.Subject, subjectWidth).PadRight(subjectWidth)} " +
                    $"{validFrom.PadRight(validFromWidth)} " +
                    $"{validTo.PadRight(validToWidth)} " +
                    $"{cert.Count.ToString(CultureInfo.InvariantCulture).PadLeft(countWidth)}");
            }

            output.WriteLine();
            output.WriteLine($"Total: {ordered.Count} unique certificate(s), " +
                             $"{ordered.Sum(c => c.Count)} event(s).");
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;
            return value.Length <= maxLength ? value : value.Substring(0, maxLength - 3) + "...";
        }

        private static string FormatTimestamp(DateTime ts)
        {
            return ts.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        }
    }
}
