namespace CertAuditor
{
    /// <summary>
    /// Tracks a distinct certificate (by thumbprint) observed during a capture run,
    /// along with how many matching events were seen for it.
    /// </summary>
    public class SeenCertificate
    {
        public string Thumbprint { get; set; }
        public string Subject { get; set; }
        public int Count { get; set; }
    }
}
