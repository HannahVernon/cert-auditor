using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Xml;
using System.Xml.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
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
        private volatile bool _disposed;
        private long _xmlParseErrors;

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

            var isNewFile = !File.Exists(logFilePath);
            var utf8NoBom = new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
            _logWriter = new StreamWriter(logFilePath, append: true, encoding: utf8NoBom);
            _logWriter.AutoFlush = true;

            if (_logWriter.BaseStream.Length == 0)
            {
                _logWriter.WriteLine(CertUsageEvent.HeaderLine);
            }

            // Set restrictive ACLs on new log files (Administrators + SYSTEM only)
            if (isNewFile)
            {
                try
                {
                    var fi = new FileInfo(logFilePath);
                    var acl = fi.GetAccessControl();
                    acl.SetAccessRuleProtection(true, false);
                    acl.AddAccessRule(new FileSystemAccessRule(
                        new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                        FileSystemRights.FullControl,
                        AccessControlType.Allow));
                    acl.AddAccessRule(new FileSystemAccessRule(
                        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                        FileSystemRights.FullControl,
                        AccessControlType.Allow));
                    fi.SetAccessControl(acl);
                }
                catch
                {
                    ConsoleHelpers.WriteInfo(
                        "Warning: Could not set restrictive ACLs on the log file. " +
                        "Verify the log directory permissions manually.");
                }
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

                // Clean up any stale ETW session from a previous crash
                try
                {
                    var stale = TraceEventSession.GetActiveSession(SessionName);
                    if (stale != null)
                    {
                        ConsoleHelpers.WriteInfo(
                            "Cleaning up stale ETW session from a previous run...");
                        stale.Stop();
                        stale.Dispose();
                    }
                }
                catch { /* no stale session or cleanup failed — proceed anyway */ }

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

            // Only apply the store filter when the event actually reports a store name.
            // Many CAPI2 events (especially chain validation) omit store info from their XML,
            // so we let those through rather than silently dropping them.
            if (!string.IsNullOrEmpty(_storeFilter) &&
                !string.IsNullOrEmpty(evt.StoreName) &&
                !string.Equals(evt.StoreName, _storeFilter, StringComparison.OrdinalIgnoreCase))
                return;

            if (_thumbprintFilter != null && _thumbprintFilter.Count > 0 &&
                !_thumbprintFilter.Contains(evt.Thumbprint))
                return;

            lock (_writeLock)
            {
                if (_disposed) return;
                _logWriter.WriteLine(evt.ToLogLine());
            }

            var count = Interlocked.Increment(ref _eventCount);

            if (count % 100 == 0)
            {
                Console.Error.Write($"\rEvents captured: {count}");

                // Warn once when log file exceeds 100 MB
                if (count == 100)
                {
                    // no-op: too early to check
                }
                else if (count % 10000 == 0)
                {
                    try
                    {
                        var size = new FileInfo(_logWriter.BaseStream is FileStream fs
                            ? fs.Name : string.Empty).Length;
                        if (size > 100 * 1024 * 1024)
                        {
                            ConsoleHelpers.WriteInfo(
                                $"\nWarning: Log file has exceeded 100 MB ({size / (1024 * 1024)} MB). " +
                                "Consider stopping the capture to prevent disk exhaustion.");
                        }
                    }
                    catch { /* file size check is best-effort */ }
                }
            }
        }

        private CertUsageEvent ParseEvent(TraceEvent data)
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
        private void ParseCapi2Xml(string xml, CertUsageEvent evt)
        {
            try
            {
                var settings = new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null
                };

                XDocument doc;
                using (var reader = XmlReader.Create(new StringReader(xml), settings))
                {
                    doc = XDocument.Load(reader);
                }

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
            catch (XmlException)
            {
                if (Interlocked.Increment(ref _xmlParseErrors) == 1)
                {
                    ConsoleHelpers.WriteInfo(
                        "Warning: XML parsing failed for a CAPI2 event. " +
                        "Some event fields may be incomplete.");
                }
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

            lock (_writeLock)
            {
                _disposed = true;
                try { _logWriter?.Dispose(); } catch { }
            }

            var parseErrors = Interlocked.Read(ref _xmlParseErrors);
            if (parseErrors > 0)
            {
                ConsoleHelpers.WriteInfo(
                    $"Note: {parseErrors} event(s) had XML parsing errors during capture.");
            }
        }
    }
}
