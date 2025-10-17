using System.CommandLine;
using System.CommandLine.Parsing;
using System.Net;


namespace Responder
{
    class Program
    {
        static async Task Main(string[] args)
        {

            Option<string> advertisedAddressArg = new("--advertise")
            {
                Description = "IP address to advertise in response to mDNS/LLMNR traffic."
            };
            advertisedAddressArg.Aliases.Add("-a");
            advertisedAddressArg.Required = true;

            Option<string> bindAddressArg = new("--bind")
            {
                Description = "Local address to bind to.",
                DefaultValueFactory = ParseResult=> "0.0.0.0",

            };
            bindAddressArg.Aliases.Add("-b");

            Option<int> durationArg = new("--duration")
            {
                Description = "Time in Minutes to listen for traffic.",
                DefaultValueFactory = ParseResult => 60,

            };
            durationArg.Aliases.Add("-d");

            var root = new RootCommand("WPAD Responder");

            root.Options.Add(advertisedAddressArg);
            root.Options.Add(bindAddressArg);
            root.Options.Add(durationArg);

            var parseResult = root.Parse(args);
            if (parseResult.Errors.Count > 0)
            {
                foreach (ParseError parseError in parseResult.Errors)
                {
                    Console.Error.WriteLine(parseError.Message);
                }
                root.Parse("-h").Invoke();
                return;
            }

            var advertisedAddressString = parseResult.GetValue<string>("--advertise");
            var bindAddressString = parseResult.GetValue<string>("--bind");
            int duration = parseResult.GetValue<int>("--duration");

                if (!IPAddress.TryParse(advertisedAddressString, out var advertisedAddress))
                {
                    Console.WriteLine($"Invalid Advertisement IP: {advertisedAddressString}");
                    return;
                }

                if (!IPAddress.TryParse(bindAddressString, out var bindAddress))
                {
                    Console.WriteLine($"Invalid Bind IP: {bindAddressString}");
                    return;
                }

                Console.WriteLine($"Starting WPAD Responder: Bind={bindAddress}, Advertise={advertisedAddress}, Duration={duration}m");

                var mdnsSniffer = new MdnsSniffer(advertisedAddress, bindAddress, duration);
                var llmnrSniffer = new LLMNRSniffer(advertisedAddress, bindAddress, duration);
                await Task.WhenAll(
                    mdnsSniffer.RunAsync(),
                    llmnrSniffer.RunAsync()
                );
                
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Closing Bind Port and Terminating program.");

            }

        }
    }
