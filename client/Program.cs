using System;
using System.Threading.Tasks;
using stungun.common.client;
using stungun.common.core;

namespace stungun.client
{
    class Program
    {
        public static async Task Main(string[] args)
        {
            await Console.Out.WriteLineAsync("stun-client 1.0");

            if (args == null
                || args.Length < 1
                || (args.Length == 1 && (string.Compare(args[0], "?", StringComparison.InvariantCultureIgnoreCase) == 0))
                || (args.Length == 1 && (string.Compare(args[0], "-?", StringComparison.InvariantCultureIgnoreCase) == 0))
                || (args.Length == 1 && (string.Compare(args[0], "/?", StringComparison.InvariantCultureIgnoreCase) == 0))
                || (args.Length == 1 && (string.Compare(args[0], "/help", StringComparison.InvariantCultureIgnoreCase) == 0))
                || (args.Length == 1 && (string.Compare(args[0], "--help", StringComparison.InvariantCultureIgnoreCase) == 0))
                || (args.Length == 1 && (string.Compare(args[0], "-help", StringComparison.InvariantCultureIgnoreCase) == 0))
                || (args.Length == 1 && (string.Compare(args[0], "help", StringComparison.InvariantCultureIgnoreCase) == 0)))
            {
                Console.WriteLine("Usage: stun-client <hostname> [proto]");
                Console.WriteLine("\t<hostname> is the hostname of the STUN server to which to make a binding request");
                Console.WriteLine("\t[proto] is one of tcp or udp.  If not specified, udp is assumed");
                await Console.Error.WriteLineAsync("No hostname specified.  Try stun.stunprotocol.org to demo this tool.");
                return;
            }

            var hostname = args[0];
            var proto = args.Length < 2 ? "udp" : ((string.Compare(args[1], "tcp", StringComparison.InvariantCultureIgnoreCase) == 0) ? "tcp" : "udp");

            IStunClient stunClient;
            if (string.Compare(proto, "tcp", StringComparison.InvariantCultureIgnoreCase) == 0)
                stunClient = new StunTcpClient(hostname);
            else
                stunClient = new StunUdpClient(hostname);

            using (stunClient)
            {
                var resp = await stunClient.BindingRequestAsync();

                await Console.Out.WriteLineAsync($"querying {resp.RemoteEndpoint.Address}:{resp.RemoteEndpoint.Port} from {resp.LocalEndpoint.Address}:{resp.LocalEndpoint.Port} over {proto.ToUpperInvariant()}");
                if (resp.Success)
                {
                    var msg = resp.Message!;
                    await Console.Out.WriteLineAsync($"reply type {(ushort)msg.Header.Type} {Enum.GetName(typeof(MessageType), msg!.Header.Type)}");
                    await Console.Out.WriteLineAsync($" length: {msg!.Header.MessageLength + 20}");
                    await Console.Out.WriteLineAsync($" length of attributes: {msg!.Header.MessageLength}");
                    if (msg.Attributes != null)
                        foreach (var attr in msg.Attributes)
                        {
                            await Console.Out.WriteLineAsync($" attribute type 0x{(ushort)attr.Type:x2} {Enum.GetName(typeof(AttributeType), attr.Type)}, value length: {attr.AttributeLength}");
                            await Console.Out.WriteLineAsync($"  {attr.ToString()}");
                        }
                }
                else
                    await Console.Error.WriteLineAsync(resp.ErrorMessage);
            }

            var disco = new DiscoveryClient();
            var discoResult = await disco.DiscoverUdpRfc3489Async();
            await Console.Out.WriteLineAsync($"NAT Discovery via UDP per RFC 3489: {discoResult}");
        }
    }
}
