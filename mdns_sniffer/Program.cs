using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using CommandLine;

namespace WPADResponder
{
    // Define CLI options
    public class Options
    {
        [Option('a', "advertise", Required = true, HelpText = "IPv4 address to advertise in responses (e.g., 192.168.1.10).")]
        public string Advertise { get; set; }

        [Option('b', "bind", Required = false, Default = "0.0.0.0", HelpText = "Local IPv4 address to bind (default: 0.0.0.0).")]
        public string Bind { get; set; }

        [Option('d', "duration", Required = false, Default = 60, HelpText = "Listening duration in minutes (default: 60).")]
        public int Duration { get; set; }
    }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            return Parser.Default.ParseArguments<Options>(args)
                .MapResult(
                    (Options opts) => Run(opts),
                    errs => 1
                );
        }

        private static int Run(Options opts)
        {
            // Validate IPs
            if (!IPAddress.TryParse(opts.Advertise, out var advertised))
            {
                Console.Error.WriteLine($"Invalid --advertise IP: {opts.Advertise}");
                return 1;
            }
            if (!IPAddress.TryParse(opts.Bind, out var bind))
            {
                Console.Error.WriteLine($"Invalid --bind IP: {opts.Bind}");
                return 1;
            }
            if (advertised.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
                bind.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            {
                Console.Error.WriteLine("Only IPv4 is supported for --advertise and --bind.");
                return 1;
            }
            if (opts.Duration <= 0)
            {
                Console.Error.WriteLine("Invalid --duration. Must be a positive integer (minutes).");
                return 1;
            }

            Console.Write($"Starting WPAD Responder\n");
            Console.WriteLine($"  Bind:       {bind}");
            Console.WriteLine($"  Advertise:  {advertised}");
            Console.WriteLine($"  Duration:   {opts.Duration} minute(s)");
            Console.WriteLine();

            var mdns = new MdnsSniffer(advertised, bind, opts.Duration);
            var llmnr = new LLMNRSniffer(advertised, bind, opts.Duration);

            try
            {
                Task.WaitAll(
                    mdns.RunAsync(),
                    llmnr.RunAsync()
                );
            }
            catch (AggregateException ae)
            {
                foreach (var ex in ae.InnerExceptions)
                    Console.Error.WriteLine("Error: " + ex.Message);
                return 1;
            }

            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Closing Bind Port and terminating program.");
            return 0;
        }
    }
}