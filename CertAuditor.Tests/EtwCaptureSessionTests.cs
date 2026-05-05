using System;
using System.Collections.Generic;
using Xunit;

namespace CertAuditor.Tests
{
    public class EtwCaptureSessionTests
    {
        [Fact]
        public void AllowedEventIds_ContainsExpectedIds()
        {
            Assert.True(EtwCaptureSession.AllowedEventIds.ContainsKey(11));
            Assert.True(EtwCaptureSession.AllowedEventIds.ContainsKey(30));
            Assert.True(EtwCaptureSession.AllowedEventIds.ContainsKey(41));
            Assert.True(EtwCaptureSession.AllowedEventIds.ContainsKey(81));
            Assert.True(EtwCaptureSession.AllowedEventIds.ContainsKey(90));
            Assert.Equal(5, EtwCaptureSession.AllowedEventIds.Count);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(10)]
        [InlineData(31)]
        [InlineData(40)]
        [InlineData(50)]
        [InlineData(100)]
        [InlineData(8200)]
        public void AllowedEventIds_RejectsInvalidIds(int invalidId)
        {
            Assert.False(EtwCaptureSession.AllowedEventIds.ContainsKey(invalidId));
        }

        /// <summary>
        /// Integration test: verifies an ETW session can start and stop cleanly.
        /// Requires administrator privileges.
        /// </summary>
        [Fact]
        [Trait("Category", "Integration")]
        public void Capture_StartsAndStops_WithShortDuration()
        {
            if (!ConsoleHelpers.IsElevated())
            {
                // Skip gracefully when not elevated
                return;
            }

            var logPath = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"certauditor-integration-{Guid.NewGuid():N}.log");

            try
            {
                var eventIds = new HashSet<int> { 11, 30 };
                using (var session = new EtwCaptureSession(logPath, eventIds, null, null))
                {
                    var cts = new System.Threading.CancellationTokenSource();
                    cts.CancelAfter(TimeSpan.FromSeconds(3));

                    session.Run(cts.Token, TimeSpan.FromSeconds(3));
                }

                // Verify log file was created with at least a header
                Assert.True(System.IO.File.Exists(logPath));
                var content = System.IO.File.ReadAllText(logPath);
                Assert.StartsWith("Timestamp", content);
            }
            finally
            {
                try { System.IO.File.Delete(logPath); }
                catch { }
            }
        }
    }
}
