using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using stungun.common.core;

namespace stungun.common.server
{
    public class StunUdpServer : IDisposable
    {
        private static readonly Queue<string> _transactionLog = new Queue<string>(100);

        // To detect redundant calls
        private bool _disposed = false;

        private UdpClient? UdpServer { get; set; }

        private Task? ServerLoop { get; set; }

        public IReadOnlyCollection<IPEndPoint> Endpoints { get; set; }

        public StunUdpServer(
            IEnumerable<IPEndPoint> endpoints)
        {
            if (endpoints == null)
                throw new ArgumentNullException(nameof(endpoints));
            this.Endpoints = endpoints.ToList().AsReadOnly();
        }

        ~StunUdpServer() => Dispose(false);

        public void Start(ushort port, CancellationToken cancellationToken = default(CancellationToken))
        {
            this.ServerLoop?.Dispose();
            this.UdpServer?.Dispose();

            this.UdpServer = new UdpClient(port);
            this.ServerLoop = new Task(async () => await ProcessingLoop(this.UdpServer, cancellationToken));
            this.ServerLoop.Start();
        }

        public void Stop()
        {
            this.ServerLoop?.Dispose();
            this.ServerLoop = null;
            this.UdpServer?.Dispose();
            this.UdpServer = null;
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
                this.ServerLoop?.Dispose();
                this.ServerLoop = null;
                this.UdpServer?.Dispose();
                this.UdpServer = null;
            }

            // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
            // TODO: set large fields to null.

            _disposed = true;
        }

        private static async Task ProcessingLoop(UdpClient udpServer, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (udpServer is null)
                throw new ArgumentNullException(nameof(udpServer));

            do
            {
                try
                {
                    var udpReceive = await udpServer.ReceiveAsync();
                    var req = Message.Parse(udpReceive.Buffer);

                    switch (req.Header.Type)
                    {
                        case MessageType.BindingRequest:
                            {
                                req.PrintDebug();

                                if (_transactionLog.Count > 99)
                                    _transactionLog.Dequeue();

                                var txns = Encoding.UTF8.GetString(req.Header.TransactionId);

                                if (_transactionLog.Contains(txns))
                                    continue;

                                _transactionLog.Enqueue(txns);

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

                                break;
                            }
                        case MessageType.BindingError:
                            req.PrintDebug();
                            break;
                        default:
                            break;
                    }
                }
                catch (Exception ex)
                {
                    await Console.Error.WriteLineAsync(ex.ToString());
                }

            } while (!cancellationToken.IsCancellationRequested);
        }
    }
}
