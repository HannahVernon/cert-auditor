using System;
using Xunit;

namespace CertAuditor.Tests
{
    public class DurationParserTests
    {
        [Theory]
        [InlineData("30s", 30)]
        [InlineData("1s", 1)]
        [InlineData("999s", 999)]
        public void TryParse_Seconds_ReturnsCorrectTimeSpan(string input, int expectedSeconds)
        {
            var result = DurationParser.TryParse(input);

            Assert.NotNull(result);
            Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), result.Value);
        }

        [Theory]
        [InlineData("10m", 10)]
        [InlineData("1m", 1)]
        [InlineData("120m", 120)]
        public void TryParse_Minutes_ReturnsCorrectTimeSpan(string input, int expectedMinutes)
        {
            var result = DurationParser.TryParse(input);

            Assert.NotNull(result);
            Assert.Equal(TimeSpan.FromMinutes(expectedMinutes), result.Value);
        }

        [Theory]
        [InlineData("1h", 1)]
        [InlineData("24h", 24)]
        public void TryParse_Hours_ReturnsCorrectTimeSpan(string input, int expectedHours)
        {
            var result = DurationParser.TryParse(input);

            Assert.NotNull(result);
            Assert.Equal(TimeSpan.FromHours(expectedHours), result.Value);
        }

        [Theory]
        [InlineData("1d", 1)]
        [InlineData("7d", 7)]
        [InlineData("30d", 30)]
        public void TryParse_Days_ReturnsCorrectTimeSpan(string input, int expectedDays)
        {
            var result = DurationParser.TryParse(input);

            Assert.NotNull(result);
            Assert.Equal(TimeSpan.FromDays(expectedDays), result.Value);
        }

        [Theory]
        [InlineData("10S")]
        [InlineData("5M")]
        [InlineData("2H")]
        [InlineData("1D")]
        public void TryParse_CaseInsensitive(string input)
        {
            var result = DurationParser.TryParse(input);

            Assert.NotNull(result);
        }

        [Theory]
        [InlineData("  10m  ")]
        [InlineData(" 5s")]
        [InlineData("1h ")]
        public void TryParse_TrimsWhitespace(string input)
        {
            var result = DurationParser.TryParse(input);

            Assert.NotNull(result);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("abc")]
        [InlineData("10")]
        [InlineData("s")]
        [InlineData("10x")]
        [InlineData("0s")]
        [InlineData("-5m")]
        [InlineData("1.5h")]
        [InlineData("10 minutes")]
        public void TryParse_InvalidInput_ReturnsNull(string input)
        {
            var result = DurationParser.TryParse(input);

            Assert.Null(result);
        }

        [Fact]
        public void Parse_ValidInput_ReturnsTimeSpan()
        {
            var result = DurationParser.Parse("10m");

            Assert.Equal(TimeSpan.FromMinutes(10), result);
        }

        [Fact]
        public void Parse_InvalidInput_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => DurationParser.Parse("invalid"));
        }
    }
}
