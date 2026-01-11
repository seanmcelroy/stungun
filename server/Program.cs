using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

using stungun.common.server;

namespace server
{
    class Program
    {
        public static async Task Main(string[] args)
        {
            await Console.Out.WriteLineAsync("stun-server 1.0");

            var addresses = Dns.GetHostEntry(Dns.GetHostName()).AddressList;
            foreach (var address in addresses.Where(a => !a.IsIPv6LinkLocal))
                await Console.Out.WriteLineAsync($"Discovered IP {address}");

            var endpoints = addresses
                .Where(a => !a.IsIPv6LinkLocal)
                .Select(a => new IPEndPoint(a, 3478)).ToArray();
            var stunUdpServer = new StunUdpServer(endpoints);
            stunUdpServer.Start(3478);
            Console.ReadLine();
        }
    }
}
