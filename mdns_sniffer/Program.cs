using System;
using System.Collections.Generic;
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

            if (args.Length < 3)
            {
                Console.WriteLine("Usage: mdns_responder <advertise-ip> <bind-ip> <duration (s)>");
                return;
            }

            if (!IPAddress.TryParse(args[0], out var advertisedAddress))
            {
                Console.WriteLine($"Invalid Advertisement IP: {args[0]}");
                return;
            }

            if (!IPAddress.TryParse(args[1], out var bindAddress))
            {
                Console.WriteLine($"Invalid Bind IP: {args[1]}");
                return;
            }

            if (!int.TryParse(args[2], out var duration))
            {
                Console.WriteLine($"Invalid Time: {args[2]}");
                return;
            }

            var sniffer = new MdnsSniffer(advertisedAddress, bindAddress, duration);
            await sniffer.RunAsync();


        }
    }
}