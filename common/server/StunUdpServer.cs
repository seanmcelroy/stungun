using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using stungun.common.core;

namespace stungun.common.server
{
    public class StunUdpServer : IDisposable
    {
        private UdpClient? udpServer;

        private Task? serverLoop;

        // To detect redundant calls
        private bool _disposed = false;

        public int Port { get; set; }

        public StunUdpServer(int port = 3478)
        {
            this.Port = port;
        }

        ~StunUdpServer() => Dispose(false);

        public void Start(CancellationToken cancellationToken = default(CancellationToken))
        {
            serverLoop?.Dispose();
            udpServer?.Dispose();
            udpServer = new UdpClient(this.Port);

            serverLoop = new Task(async () =>
            {
                do
                {
                    try
                    {
                        var udpReceive = await udpServer.ReceiveAsync();
                        var req = Message.Parse(udpReceive.Buffer);
                        req.PrintDebug();

                        if (req.Header.Type.Equals(MessageType.BindingRequest))
                        {
                            var attributeList = new List<MessageAttribute>() {
                                new MappedAddressAttribute {
                                    AddressFamily = udpReceive.RemoteEndPoint.AddressFamily,
                                    Port = (ushort)udpReceive.RemoteEndPoint.Port,
                                    IPAddress = udpReceive.RemoteEndPoint.Address
                                },
                                new XorMappedAddressAttribute(req.Header.TransactionId) {
                                    AddressFamily = udpReceive.RemoteEndPoint.AddressFamily,
                                    Port = (ushort)udpReceive.RemoteEndPoint.Port,
                                    IPAddress = udpReceive.RemoteEndPoint.Address
                                }
                            }.AsReadOnly();

                            var resp = new Message
                            {
                                Header = new MessageHeader
                                {
                                    Type = MessageType.BindingResponse,
                                    MessageLength = (ushort)attributeList.Sum(a => a.Bytes.Count),
                                    MagicCookie = req.Header.MagicCookie,
                                    TransactionId = req.Header.TransactionId
                                },
                                Attributes = attributeList
                            };

                            await Console.Error.WriteLineAsync($"Attribute count: {attributeList.Count}");

                            resp.PrintDebug();

                            var respBytes = resp.ToByteArray();
                            var bytesSent = await udpServer.SendAsync(respBytes, respBytes.Length, udpReceive.RemoteEndPoint);
                        }
                    }
                    catch (Exception ex)
                    {
                        await Console.Error.WriteLineAsync(ex.ToString());
                    }

                } while (!cancellationToken.IsCancellationRequested);
            });
            serverLoop.Start();
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
                udpServer?.Dispose();
                udpServer = null;
            }

            // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
            // TODO: set large fields to null.

            _disposed = true;
        }
    }
}
