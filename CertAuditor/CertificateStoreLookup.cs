using System;
using System.Security.Cryptography.X509Certificates;

namespace CertAuditor
{
    /// <summary>
    /// Looks up a certificate's validity period (NotBefore/NotAfter) from the
    /// Windows certificate stores by thumbprint. CAPI2 ETW events do not carry
    /// validity dates in their payload, so the end-of-run summary re-reads the
    /// actual certificate from wherever it's installed.
    /// </summary>
    public static class CertificateStoreLookup
    {
        private static readonly (StoreLocation Location, StoreName Name)[] CommonStores =
        {
            (StoreLocation.LocalMachine, StoreName.My),
            (StoreLocation.LocalMachine, StoreName.Root),
            (StoreLocation.LocalMachine, StoreName.CertificateAuthority),
            (StoreLocation.LocalMachine, StoreName.TrustedPeople),
            (StoreLocation.LocalMachine, StoreName.TrustedPublisher),
            (StoreLocation.LocalMachine, StoreName.AuthRoot),
            (StoreLocation.LocalMachine, StoreName.Disallowed),
            (StoreLocation.CurrentUser, StoreName.My),
            (StoreLocation.CurrentUser, StoreName.Root),
            (StoreLocation.CurrentUser, StoreName.TrustedPeople),
        };

        /// <summary>
        /// Attempts to find the certificate's validity period by thumbprint.
        /// If <paramref name="storeHint"/> (format "Location\StoreName", e.g.
        /// the --store filter the capture was run with) is provided, that
        /// store is checked first; otherwise a list of commonly used stores
        /// is searched. Returns null if the certificate can no longer be
        /// found anywhere searched (e.g., it was removed after being observed).
        /// </summary>
        public static (DateTime NotBefore, DateTime NotAfter)? TryGetValidity(string thumbprint, string storeHint)
        {
            if (string.IsNullOrEmpty(thumbprint))
                return null;

            if (TryParseStoreHint(storeHint, out var hintedLocation, out var hintedName))
            {
                var hinted = TryFind(hintedLocation, hintedName, thumbprint);
                if (hinted.HasValue)
                    return hinted;
            }

            foreach (var (location, name) in CommonStores)
            {
                var found = TryFind(location, name, thumbprint);
                if (found.HasValue)
                    return found;
            }

            return null;
        }

        private static (DateTime, DateTime)? TryFind(StoreLocation location, StoreName name, string thumbprint)
        {
            try
            {
                using (var store = new X509Store(name, location))
                {
                    store.Open(OpenFlags.ReadOnly);
                    var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
                    if (matches.Count > 0)
                        return (matches[0].NotBefore, matches[0].NotAfter);
                }
            }
            catch
            {
                // Store may not exist, or access may be denied - try the next one.
            }

            return null;
        }

        private static bool TryParseStoreHint(string storeHint, out StoreLocation location, out StoreName name)
        {
            location = StoreLocation.LocalMachine;
            name = StoreName.My;

            if (string.IsNullOrEmpty(storeHint))
                return false;

            var parts = storeHint.Split('\\');
            if (parts.Length != 2)
                return false;

            if (!Enum.TryParse(parts[0], true, out location))
                return false;

            if (!Enum.TryParse(parts[1], true, out name))
                return false;

            return true;
        }
    }
}
