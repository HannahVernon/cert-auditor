using Xunit;

namespace CertAuditor.Tests
{
    public class CertificateStoreLookupTests
    {
        [Fact]
        public void TryGetValidity_NullThumbprint_ReturnsNull()
        {
            Assert.Null(CertificateStoreLookup.TryGetValidity(null, null));
        }

        [Fact]
        public void TryGetValidity_EmptyThumbprint_ReturnsNull()
        {
            Assert.Null(CertificateStoreLookup.TryGetValidity(string.Empty, null));
        }

        [Fact]
        public void TryGetValidity_UnknownThumbprint_ReturnsNull()
        {
            // No certificate anywhere will ever have this thumbprint.
            Assert.Null(CertificateStoreLookup.TryGetValidity("0000000000000000000000000000000000000000", null));
        }

        [Fact]
        public void TryGetValidity_UnknownThumbprint_WithInvalidStoreHint_StillSearchesCommonStores()
        {
            // An invalid/unparsable store hint should not throw - it should just
            // fall back to searching the common store list.
            Assert.Null(CertificateStoreLookup.TryGetValidity(
                "0000000000000000000000000000000000000000", "not-a-valid-hint"));
        }
    }
}
