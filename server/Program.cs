using System;
using System.Threading.Tasks;

using stungun.common.server;

namespace server
{
    class Program
    {
        public static async Task Main(string[] args)
        {
            await Console.Out.WriteLineAsync("stun-server 1.0");

            var stunUdpServer = new StunUdpServer();

            stunUdpServer.Start();
            do
            {


            } while (true);
        }
    }
}
