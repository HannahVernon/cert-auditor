using System;
using System.Threading;

namespace CertAuditor
{
    /// <summary>
    /// Handles Ctrl+C graceful shutdown and console output formatting.
    /// </summary>
    public static class ConsoleHelpers
    {
        private static readonly CancellationTokenSource Cts = new CancellationTokenSource();

        /// <summary>
        /// Gets a cancellation token that is cancelled when the user presses Ctrl+C.
        /// </summary>
        public static CancellationToken CancellationToken => Cts.Token;

        /// <summary>
        /// Installs the Ctrl+C handler. Call once at startup.
        /// </summary>
        public static void InstallCancelHandler()
        {
            Console.CancelKeyPress += (sender, args) =>
            {
                args.Cancel = true;
                Console.Error.WriteLine();
                Console.Error.WriteLine("Shutting down (Ctrl+C received)...");
                Cts.Cancel();
            };
        }

        /// <summary>
        /// Returns true if the current process is running with administrator privileges.
        /// </summary>
        public static bool IsElevated()
        {
            using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
            {
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
        }

        public static void WriteError(string message)
        {
            Console.Error.WriteLine($"ERROR: {message}");
        }

        public static void WriteInfo(string message)
        {
            Console.Error.WriteLine(message);
        }
    }
}
