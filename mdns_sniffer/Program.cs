using System;
using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Responder
{
    class Program
    {
        static async Task Main(string[] args)
        {

            Option<string> advertisedAddressArg = new("--advertise")
            {
                Description = "IP address to advertise in response to mDNS traffic."
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

            var root = new RootCommand("mDNS responder");

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

                var sniffer = new MdnsSniffer(advertisedAddress, bindAddress, duration);
                await sniffer.RunAsync();

            }

        }
    }
