using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Xml.Linq;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace CertAuditor
{
    /// <summary>
    /// Manages a real-time ETW session subscribed to the CAPI2 provider.
    /// Parses certificate-usage events and writes them to a log file.
    /// </summary>
    public sealed class EtwCaptureSession : IDisposable
    {
        private const string SessionName = "CertAuditor-CAPI2";
        private static readonly Guid Capi2ProviderGuid =
            new Guid("5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB");

        /// <summary>
        /// Allowed CAPI2 event IDs and their descriptions.
        /// </summary>
        public static readonly Dictionary<int, string> AllowedEventIds = new Dictionary<int, string>
        {
            { 30, "BuildChain — certificate chain validation" },
            { 40, "VerifyRevocation — revocation check (CRL/OCSP)" },
            { 50, "X509Objects — certificate object opened from store" },
            { 70, "RetrieveObjectByUrlWire — CRL/OCSP fetch" },
            { 90, "AutoEnrollment — auto-enrollment activity" }
        };

        private readonly HashSet<int> _eventIds;
        private readonly string _storeFilter;
        private readonly HashSet<string> _thumbprintFilter;
        private readonly StreamWriter _logWriter;
        private readonly object _writeLock = new object();
        private TraceEventSession _session;
        private long _eventCount;

        public long EventCount => Interlocked.Read(ref _eventCount);

        public EtwCaptureSession(
            string logFilePath,
            IEnumerable<int> eventIds,
            string storeFilter,
            IEnumerable<string> thumbprints)
        {
            _eventIds = new HashSet<int>(eventIds);
            _storeFilter = storeFilter;
            _thumbprintFilter = thumbprints != null
                ? new HashSet<string>(thumbprints, StringComparer.OrdinalIgnoreCase)
                : null;

            var fileExists = File.Exists(logFilePath);
            _logWriter = new StreamWriter(logFilePath, append: true, encoding: System.Text.Encoding.UTF8);
            _logWriter.AutoFlush = true;

            if (!fileExists || new FileInfo(logFilePath).Length == 0)
            {
                _logWriter.WriteLine(CertUsageEvent.HeaderLine);
            }
        }

        /// <summary>
        /// Starts the ETW capture session. Blocks until the cancellation token is triggered
        /// or the optional duration elapses.
        /// </summary>
        public void Run(CancellationToken cancellationToken, TimeSpan? duration)
        {
            using (var durationCts = new CancellationTokenSource())
            using (var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                       cancellationToken, durationCts.Token))
            {
                if (duration.HasValue)
                {
                    durationCts.CancelAfter(duration.Value);
                }

                _session = new TraceEventSession(SessionName);

                linkedCts.Token.Register(() =>
                {
                    try { _session?.Stop(); }
                    catch { /* session may already be disposed */ }
                });

                _session.EnableProvider(Capi2ProviderGuid);

                _session.Source.Dynamic.All += OnEvent;

                ConsoleHelpers.WriteInfo($"Capturing CAPI2 events (IDs: {string.Join(", ", _eventIds.OrderBy(x => x))})...");
                if (!string.IsNullOrEmpty(_storeFilter))
                    ConsoleHelpers.WriteInfo($"Store filter: {_storeFilter}");
                if (_thumbprintFilter != null && _thumbprintFilter.Count > 0)
                    ConsoleHelpers.WriteInfo($"Thumbprint filter: {string.Join(", ", _thumbprintFilter)}");
                if (duration.HasValue)
                    ConsoleHelpers.WriteInfo($"Duration: {duration.Value}");
                ConsoleHelpers.WriteInfo("Press Ctrl+C to stop.");
                ConsoleHelpers.WriteInfo(string.Empty);

                _session.Source.Process();
            }

            ConsoleHelpers.WriteInfo(string.Empty);
            ConsoleHelpers.WriteInfo($"Capture complete. {EventCount} event(s) written.");
        }

        private void OnEvent(TraceEvent data)
        {
            if (!_eventIds.Contains((int)data.ID))
                return;

            var evt = ParseEvent(data);
            if (evt == null)
                return;

            if (!string.IsNullOrEmpty(_storeFilter) &&
                !string.Equals(evt.StoreName, _storeFilter, StringComparison.OrdinalIgnoreCase))
                return;

            if (_thumbprintFilter != null && _thumbprintFilter.Count > 0 &&
                !_thumbprintFilter.Contains(evt.Thumbprint))
                return;

            lock (_writeLock)
            {
                _logWriter.WriteLine(evt.ToLogLine());
            }

            Interlocked.Increment(ref _eventCount);

            Console.Error.Write($"\rEvents captured: {EventCount}");
        }

        private static CertUsageEvent ParseEvent(TraceEvent data)
        {
            var evt = new CertUsageEvent
            {
                Timestamp = data.TimeStamp,
                EventId = (int)data.ID,
                ProcessId = data.ProcessID,
                ProcessName = GetProcessName(data.ProcessID),
                Result = 0
            };

            // Try to extract certificate details from the event's XML payload
            try
            {
                var xmlPayload = data.ToString();
                if (!string.IsNullOrEmpty(xmlPayload))
                {
                    ExtractFromPayload(data, evt);
                }
            }
            catch
            {
                // If XML parsing fails, capture what we can
            }

            if (string.IsNullOrEmpty(evt.Thumbprint))
                evt.Thumbprint = string.Empty;
            if (string.IsNullOrEmpty(evt.Subject))
                evt.Subject = string.Empty;
            if (string.IsNullOrEmpty(evt.Issuer))
                evt.Issuer = string.Empty;
            if (string.IsNullOrEmpty(evt.StoreName))
                evt.StoreName = string.Empty;

            return evt;
        }

        private static void ExtractFromPayload(TraceEvent data, CertUsageEvent evt)
        {
            // CAPI2 events store details in named payload fields or XML.
            // The exact field names depend on the event ID.
            // We attempt multiple extraction strategies.

            for (int i = 0; i < data.PayloadNames.Length; i++)
            {
                var name = data.PayloadNames[i];
                var value = data.PayloadValue(i);
                if (value == null) continue;

                var strValue = value.ToString();

                switch (name.ToLowerInvariant())
                {
                    case "certificate":
                    case "certificatedetails":
                    case "userdata":
                        TryParseXmlFragment(strValue, evt);
                        break;
                    case "thumbprint":
                    case "sha1hash":
                        evt.Thumbprint = strValue;
                        break;
                    case "subjectname":
                    case "subject":
                        evt.Subject = strValue;
                        break;
                    case "issuername":
                    case "issuer":
                        evt.Issuer = strValue;
                        break;
                    case "storename":
                    case "store":
                        evt.StoreName = strValue;
                        break;
                    case "hresult":
                    case "result":
                    case "status":
                        if (int.TryParse(strValue, out var hr))
                            evt.Result = hr;
                        break;
                }
            }

            // Fallback: try parsing the full event string as XML
            if (string.IsNullOrEmpty(evt.Thumbprint))
            {
                try
                {
                    TryParseXmlFragment(data.ToString(), evt);
                }
                catch { /* not XML, that's fine */ }
            }
        }

        private static void TryParseXmlFragment(string xml, CertUsageEvent evt)
        {
            if (string.IsNullOrEmpty(xml) || !xml.Contains("<"))
                return;

            try
            {
                var doc = XDocument.Parse(xml);
                var ns = doc.Root?.Name.Namespace ?? XNamespace.None;

                var thumbEl = doc.Descendants()
                    .FirstOrDefault(e => e.Name.LocalName.Equals("sha1Hash", StringComparison.OrdinalIgnoreCase)
                                      || e.Name.LocalName.Equals("thumbPrint", StringComparison.OrdinalIgnoreCase)
                                      || e.Name.LocalName.Equals("thumbprint", StringComparison.OrdinalIgnoreCase));
                if (thumbEl != null && string.IsNullOrEmpty(evt.Thumbprint))
                    evt.Thumbprint = thumbEl.Value.Trim().Replace(" ", "");

                var subjectEl = doc.Descendants()
                    .FirstOrDefault(e => e.Name.LocalName.Equals("subjectName", StringComparison.OrdinalIgnoreCase)
                                      || e.Name.LocalName.Equals("subject", StringComparison.OrdinalIgnoreCase));
                if (subjectEl != null && string.IsNullOrEmpty(evt.Subject))
                    evt.Subject = subjectEl.Value.Trim();

                var issuerEl = doc.Descendants()
                    .FirstOrDefault(e => e.Name.LocalName.Equals("issuerName", StringComparison.OrdinalIgnoreCase)
                                      || e.Name.LocalName.Equals("issuer", StringComparison.OrdinalIgnoreCase));
                if (issuerEl != null && string.IsNullOrEmpty(evt.Issuer))
                    evt.Issuer = issuerEl.Value.Trim();

                var storeEl = doc.Descendants()
                    .FirstOrDefault(e => e.Name.LocalName.Equals("storeLocation", StringComparison.OrdinalIgnoreCase)
                                      || e.Name.LocalName.Equals("storeName", StringComparison.OrdinalIgnoreCase));
                if (storeEl != null && string.IsNullOrEmpty(evt.StoreName))
                    evt.StoreName = storeEl.Value.Trim();

                var resultEl = doc.Descendants()
                    .FirstOrDefault(e => e.Name.LocalName.Equals("hResult", StringComparison.OrdinalIgnoreCase)
                                      || e.Name.LocalName.Equals("result", StringComparison.OrdinalIgnoreCase));
                if (resultEl != null && int.TryParse(resultEl.Value.Trim(), out var hr))
                    evt.Result = hr;
            }
            catch
            {
                // Not valid XML — skip
            }
        }

        private static string GetProcessName(int processId)
        {
            try
            {
                using (var proc = Process.GetProcessById(processId))
                {
                    return proc.ProcessName;
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        public void Dispose()
        {
            try { _session?.Dispose(); } catch { }
            try { _logWriter?.Dispose(); } catch { }
        }
    }
}
