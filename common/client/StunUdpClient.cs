using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using stungun.common.core;

namespace stungun.common.client
{
    public class StunUdpClient : IStunClient, IDisposable
    {
        private UdpClient? udpClient;
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

        public async Task<MessageResponse> BindingRequestAsync(
            IList<MessageAttribute>? attributes = null,
            int connectTimeout = 5000,
            int recvTimeout = 5000,
            CancellationToken cancellationToken = default(CancellationToken),
            byte[]? customTransactionId = null)
        {
            byte[] responseBytes;

            var message = Message.CreateBindingRequest(attributes, customTransactionId);
            message.PrintDebug();
            var messageBytes = message.ToByteArray();
            await Console.Error.WriteAsync("SENDING:  ");
            await Console.Error.WriteLineAsync(messageBytes.Select(b => $"{b:x2}").Aggregate((c, n) => c + n));

            if (udpClient == null)
                throw new ObjectDisposedException(nameof(udpClient));

            udpClient.Connect(this.Hostname, this.Port);

            if (udpClient.Client.LocalEndPoint is not IPEndPoint localEndpoint)
                throw new NotImplementedException("This client can only handle IP endpoints");
            if (udpClient.Client.RemoteEndPoint is not IPEndPoint remoteEndpoint)
                throw new NotImplementedException("This client can only handle IP endpoints");

            var sw = new Stopwatch();
            sw.Start();

            using (var ms = new MemoryStream())
            {
                ushort bytesRead = 0, totalBytesRead = 0, messageLength = 0;

                await udpClient.SendAsync(messageBytes, messageBytes.Length);
                do
                {
                    var udpReceiveTask = udpClient.ReceiveAsync();
                    if (await Task.WhenAny(udpReceiveTask, Task.Delay(recvTimeout)) != udpReceiveTask)
                        return new MessageResponse
                        {
                            LocalEndpoint = localEndpoint,
                            RemoteEndpoint = remoteEndpoint,
                            Success = false,
                            ErrorMessage = $"Timeout receiving UDP response from {this.Hostname}:{this.Port} after {sw.ElapsedMilliseconds}ms"
                        };

                    var udpResult = await udpReceiveTask;
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

                    if (cancellationToken.IsCancellationRequested)
                        return new MessageResponse
                        {
                            LocalEndpoint = localEndpoint,
                            RemoteEndpoint = remoteEndpoint,
                            Success = false,
                            ErrorMessage = $"Receive cancelled"
                        };

                    if (sw.ElapsedMilliseconds >= recvTimeout)
                        return new MessageResponse
                        {
                            LocalEndpoint = localEndpoint,
                            RemoteEndpoint = remoteEndpoint,
                            Success = false,
                            ErrorMessage = $"Timeout receiving UDP response from {this.Hostname}:{this.Port} after {sw.ElapsedMilliseconds}ms"
                        };

                } while ((bytesRead > 0 || sw.ElapsedMilliseconds < recvTimeout) && !cancellationToken.IsCancellationRequested);
                await ms.FlushAsync(cancellationToken);
                responseBytes = ms.ToArray();
                Console.Error.WriteLine($"Sent {messageBytes.Length} bytes and read {totalBytesRead} bytes");
            }
            udpClient.Close();

            await Console.Error.WriteAsync("RECEIVED: ");
            await Console.Error.WriteLineAsync(responseBytes.Select(b => $"{b:x2}").Aggregate((c, n) => c + n));

            var msg = Message.Parse(responseBytes);
            msg.PrintDebug();

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
                udpClient = null;
            }

            // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
            // TODO: set large fields to null.

            _disposed = true;
        }
    }
}
