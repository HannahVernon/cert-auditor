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
            { 11, "BuildChain — certificate chain validation (most detailed)" },
            { 30, "VerifyChainPolicy — chain policy verification" },
            { 41, "VerifyRevocation — revocation check result (CRL/OCSP)" },
            { 81, "VerifyTrust — code signing trust verification" },
            { 90, "X509Objects — certificate objects loaded from store" }
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
                ProcessName = string.Empty,
                Result = 0,
                Thumbprint = string.Empty,
                Subject = string.Empty,
                Issuer = string.Empty,
                StoreName = string.Empty
            };

            // CAPI2 events use a single "EventWriteData" payload field containing XML
            string xmlPayload = null;
            for (int i = 0; i < data.PayloadNames.Length; i++)
            {
                if (string.Equals(data.PayloadNames[i], "EventWriteData", StringComparison.OrdinalIgnoreCase))
                {
                    var val = data.PayloadValue(i);
                    if (val != null)
                        xmlPayload = val.ToString();
                    break;
                }
            }

            if (!string.IsNullOrEmpty(xmlPayload))
            {
                ParseCapi2Xml(xmlPayload, evt);
            }

            // Fall back to process lookup if not found in XML
            if (string.IsNullOrEmpty(evt.ProcessName))
                evt.ProcessName = GetProcessName(data.ProcessID);

            return evt;
        }

        /// <summary>
        /// Parses the CAPI2 EventWriteData XML to extract certificate details.
        /// The XML structure varies by event ID but follows common patterns:
        ///   - Certificate thumbprint: fileRef attribute (e.g., "THUMB.cer")
        ///   - Subject: subjectName attribute on Certificate elements
        ///   - Issuer: Issuer child element (with CN sub-element) or IssuerCertificate element
        ///   - Process: EventAuxInfo ProcessName attribute
        ///   - Result: Result value attribute
        /// </summary>
        private static void ParseCapi2Xml(string xml, CertUsageEvent evt)
        {
            try
            {
                var doc = XDocument.Parse(xml);

                // Extract process name from <EventAuxInfo ProcessName="..."/>
                var auxInfo = doc.Descendants()
                    .FirstOrDefault(e => e.Name.LocalName == "EventAuxInfo");
                if (auxInfo != null)
                {
                    var procAttr = auxInfo.Attribute("ProcessName");
                    if (procAttr != null)
                        evt.ProcessName = procAttr.Value;
                }

                // Extract result from <Result value="..."/>
                var resultEl = doc.Descendants()
                    .FirstOrDefault(e => e.Name.LocalName == "Result");
                if (resultEl != null)
                {
                    var valAttr = resultEl.Attribute("value");
                    if (valAttr != null && int.TryParse(valAttr.Value, out var hr))
                        evt.Result = hr;
                }

                // Extract certificate details from <Certificate fileRef="THUMB.cer" subjectName="..."/>
                // Take the first Certificate element (the leaf/end-entity cert)
                var certEl = doc.Descendants()
                    .FirstOrDefault(e => e.Name.LocalName == "Certificate");
                if (certEl != null)
                {
                    var fileRef = certEl.Attribute("fileRef");
                    if (fileRef != null)
                    {
                        // fileRef is "THUMBPRINT.cer" — strip the extension
                        var thumbprint = fileRef.Value;
                        if (thumbprint.EndsWith(".cer", StringComparison.OrdinalIgnoreCase))
                            thumbprint = thumbprint.Substring(0, thumbprint.Length - 4);
                        evt.Thumbprint = thumbprint.ToUpperInvariant();
                    }

                    var subjectName = certEl.Attribute("subjectName");
                    if (subjectName != null)
                        evt.Subject = subjectName.Value;

                    // Issuer: look for <Issuer><CN>...</CN></Issuer> child
                    var issuerEl = certEl.Element("Issuer");
                    if (issuerEl != null)
                    {
                        var cn = issuerEl.Element("CN");
                        if (cn != null)
                            evt.Issuer = cn.Value;
                        else
                            evt.Issuer = string.Join(", ",
                                issuerEl.Elements().Select(e => e.Name.LocalName + "=" + e.Value));
                    }
                }

                // If no issuer from the Certificate element, try <IssuerCertificate subjectName="..."/>
                if (string.IsNullOrEmpty(evt.Issuer))
                {
                    var issuerCert = doc.Descendants()
                        .FirstOrDefault(e => e.Name.LocalName == "IssuerCertificate");
                    if (issuerCert != null)
                    {
                        var issuerSubject = issuerCert.Attribute("subjectName");
                        if (issuerSubject != null)
                            evt.Issuer = issuerSubject.Value;
                    }
                }

                // Extract store name from <CertificateStore> or store-related elements
                var storeEl = doc.Descendants()
                    .FirstOrDefault(e => e.Name.LocalName == "CertificateStore"
                                     || e.Name.LocalName == "StoreLocation");
                if (storeEl != null)
                {
                    var storeName = storeEl.Attribute("name") ?? storeEl.Attribute("storeName");
                    if (storeName != null)
                        evt.StoreName = storeName.Value;
                    else if (!string.IsNullOrEmpty(storeEl.Value))
                        evt.StoreName = storeEl.Value.Trim();
                }
            }
            catch
            {
                // XML parsing failed — keep whatever we have
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
