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
    public class StunTcpClient : IStunClient, IDisposable
    {
        private TcpClient? tcpClient;
        // To detect redundant calls
        private bool _disposed = false;

        public string Hostname { get; set; }
        public int Port { get; set; }

        public StunTcpClient(string hostname, int port = 3478)
        {
            this.Hostname = hostname;
            this.Port = port;
            tcpClient = new TcpClient();
        }

        ~StunTcpClient() => Dispose(false);

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

            if (tcpClient == null)
                throw new ObjectDisposedException(nameof(tcpClient));

            if (!tcpClient.ConnectAsync(this.Hostname, this.Port).Wait(connectTimeout, cancellationToken))
                return new MessageResponse
                {
                    LocalEndpoint = (IPEndPoint)tcpClient.Client.LocalEndPoint,
                    RemoteEndpoint = (IPEndPoint)tcpClient.Client.RemoteEndPoint,
                    Success = false,
                    ErrorMessage = $"Timeout connecting to {this.Hostname}:{this.Port} after {connectTimeout}ms"
                };

            var localEndpoint = (IPEndPoint)tcpClient.Client.LocalEndPoint;
            var remoteEndpoint = (IPEndPoint)tcpClient.Client.RemoteEndPoint;

            var sw = new Stopwatch();
            sw.Start();

            using (var ms = new MemoryStream())
            using (var ns = tcpClient.GetStream())
            {
                await ns.WriteAsync(messageBytes, 0, messageBytes.Length, cancellationToken);
                await ns.FlushAsync(cancellationToken);

                var readBuffer = new byte[8192];
                ushort bytesRead = 0, totalBytesRead = 0, messageLength = 0;
                do
                {
                    var tcpReadTask = ns.ReadAsync(readBuffer, 0, readBuffer.Length, cancellationToken);
                    if (await Task.WhenAny(tcpReadTask, Task.Delay(recvTimeout)) != tcpReadTask)
                    {
                        return new MessageResponse
                        {
                            LocalEndpoint = localEndpoint,
                            RemoteEndpoint = remoteEndpoint,
                            Success = false,
                            ErrorMessage = $"Timeout receiving TCP response from {this.Hostname}:{this.Port} after {sw.ElapsedMilliseconds}ms"
                        };
                    }

                    bytesRead = Convert.ToUInt16(await tcpReadTask);
                    totalBytesRead += bytesRead;
                    if (bytesRead > 0)
                    {
                        await ms.WriteAsync(readBuffer, 0, bytesRead, cancellationToken);
                        if (messageLength == 0)
                            messageLength = BitConverter.ToUInt16(new byte[] { readBuffer[3], readBuffer[2] }, 0);
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
                            ErrorMessage = $"Timeout receiving TCP response from {this.Hostname}:{this.Port} after {sw.ElapsedMilliseconds}ms"
                        };

                } while ((bytesRead > 0 || sw.ElapsedMilliseconds < recvTimeout) && !cancellationToken.IsCancellationRequested);
                await ms.FlushAsync(cancellationToken);
                responseBytes = ms.ToArray();
                Console.Error.WriteLine($"Sent {messageBytes.Length} bytes and read {totalBytesRead} bytes");
            }
            tcpClient.Close();

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
                tcpClient?.Dispose();
                tcpClient = null;
            }

            // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
            // TODO: set large fields to null.

            _disposed = true;
        }
    }
}
