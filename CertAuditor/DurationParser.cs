using System;
using System.Text.RegularExpressions;

namespace CertAuditor
{
    /// <summary>
    /// Parses human-friendly duration strings (30s, 10m, 1h, 2d) into TimeSpan values.
    /// </summary>
    public static class DurationParser
    {
        private static readonly Regex Pattern = new Regex(
            @"^\s*(\d+)\s*(s|m|h|d)\s*$",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>
        /// Parses a duration string. Returns null if the input is invalid.
        /// </summary>
        public static TimeSpan? TryParse(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return null;

            var match = Pattern.Match(input);
            if (!match.Success)
                return null;

            if (!long.TryParse(match.Groups[1].Value, out var value) || value <= 0)
                return null;

            var unit = match.Groups[2].Value.ToLowerInvariant();
            try
            {
                switch (unit)
                {
                    case "s": return TimeSpan.FromSeconds(value);
                    case "m": return TimeSpan.FromMinutes(value);
                    case "h": return TimeSpan.FromHours(value);
                    case "d": return TimeSpan.FromDays(value);
                    default: return null;
                }
            }
            catch (OverflowException)
            {
                return null;
            }
        }

        /// <summary>
        /// Parses a duration string. Throws ArgumentException if the input is invalid.
        /// </summary>
        public static TimeSpan Parse(string input)
        {
            var result = TryParse(input);
            if (!result.HasValue)
            {
                throw new ArgumentException(
                    $"Invalid duration '{input}'. Use a number followed by s, m, h, or d (e.g., 30s, 10m, 1h, 2d).");
            }
            return result.Value;
        }
    }
}
