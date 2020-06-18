using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using stungun.common.core;

namespace stungun.client.core
{
    public class StunUdpClient : IStunClient, IDisposable
    {
        private UdpClient udpClient;
        // To detect redundant calls
        private bool _disposed = false;

        public string Hostname { get; set; }
        public int Port { get; set; }

        public StunUdpClient(string hostname, int port = 3478)
        {
            this.Hostname = hostname;
            this.Port = port;
            udpClient = new UdpClient();
        }

        ~StunUdpClient() => Dispose(false);

        public async Task<MessageResponse> BindingRequestAsync(int connectTimeout = 5000, int recvTimeout = 5000, CancellationToken cancellationToken = default(CancellationToken))
        {
            byte[] responseBytes;

            var message = Message.CreateBindingRequest();
            message.Header.PrintDebug();
            var messageBytes = message.ToByteArray();
            await Console.Error.WriteAsync("SENDING: ");
            await Console.Error.WriteLineAsync(messageBytes.Select(b => $"{b:x2}").Aggregate((c, n) => c + n));

            udpClient.Connect(this.Hostname, this.Port);
            var localEndpoint = (IPEndPoint)udpClient.Client.LocalEndPoint;
            var remoteEndpoint = (IPEndPoint)udpClient.Client.RemoteEndPoint;

            var sw = new Stopwatch();
            sw.Start();

            using (var ms = new MemoryStream())
            {
                ushort bytesRead = 0, totalBytesRead = 0, messageLength = 0;

                await udpClient.SendAsync(messageBytes, messageBytes.Length);
                do
                {
                    var udpResult = await udpClient.ReceiveAsync();
                    bytesRead = (ushort)udpResult.Buffer.Length;
                    totalBytesRead += bytesRead;
                    if (bytesRead > 0)
                    {
                        await ms.WriteAsync(udpResult.Buffer, 0, bytesRead, cancellationToken);
                        if (messageLength == 0)
                            messageLength = BitConverter.ToUInt16(new byte[] { udpResult.Buffer[3], udpResult.Buffer[2] }, 0);
                    }

                    if (totalBytesRead >= messageLength + 20)
                        break;
                } while ((bytesRead > 0 || sw.ElapsedMilliseconds < recvTimeout) && !cancellationToken.IsCancellationRequested);
                await ms.FlushAsync(cancellationToken);
                responseBytes = ms.ToArray();
                Console.Error.WriteLine($"Sent {messageBytes.Length} bytes and read {totalBytesRead} bytes");
            }
            udpClient.Close();

            await Console.Error.WriteAsync("RECEIVED: ");
            await Console.Error.WriteLineAsync(responseBytes.Select(b => $"{b:x2}").Aggregate((c, n) => c + n));

            var msg = Message.Parse(responseBytes);
            return new MessageResponse
            {
                LocalEndpoint = localEndpoint,
                RemoteEndpoint = remoteEndpoint,
                Message = msg,
                Success = true
            };
        }

        // Public implementation of Dispose pattern callable by consumers.
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        // Protected implementation of Dispose pattern.
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                udpClient?.Dispose();
            }

            // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
            // TODO: set large fields to null.

            _disposed = true;
        }
    }
}
