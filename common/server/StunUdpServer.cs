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
                UdpReceiveResult udpReceive = default;
                try
                {
                    udpReceive = await udpServer.ReceiveAsync();

                    // Validate minimum message length
                    if (udpReceive.Buffer.Length < 20)
                    {
                        await Console.Error.WriteLineAsync($"Received malformed message: too short ({udpReceive.Buffer.Length} bytes)");
                        // Cannot send error response without valid transaction ID
                        continue;
                    }

                    var req = Message.Parse(udpReceive.Buffer);

                    switch (req.Header.Type)
                    {
                        case MessageType.BindingRequest:
                            await HandleBindingRequest(udpServer, udpReceive, req);
                            break;

                        case MessageType.BindingError:
                            req.PrintDebug();
                            break;

                        default:
                            // Unknown message type - send 400 Bad Request
                            await Console.Error.WriteLineAsync($"Unknown message type: 0x{(ushort)req.Header.Type:X4}");
                            await SendErrorResponse(
                                udpServer,
                                udpReceive.RemoteEndPoint,
                                req.Header,
                                StunErrorCodes.BadRequest,
                                $"Unknown message type: 0x{(ushort)req.Header.Type:X4}");
                            break;
                    }
                }
                catch (ArgumentOutOfRangeException ex)
                {
                    await Console.Error.WriteLineAsync($"Bad request: {ex.Message}");
                    // Try to send error response if we have enough data
                    if (udpReceive.Buffer?.Length >= 20)
                    {
                        try
                        {
                            var header = MessageHeader.Parse(udpReceive.Buffer);
                            await SendErrorResponse(
                                udpServer,
                                udpReceive.RemoteEndPoint,
                                header,
                                StunErrorCodes.BadRequest,
                                "Malformed request");
                        }
                        catch { /* Ignore errors sending error response */ }
                    }
                }
                catch (Exception ex)
                {
                    await Console.Error.WriteLineAsync($"Server error: {ex}");
                    // Try to send 500 error if possible
                    if (udpReceive.Buffer?.Length >= 20)
                    {
                        try
                        {
                            var header = MessageHeader.Parse(udpReceive.Buffer);
                            await SendErrorResponse(
                                udpServer,
                                udpReceive.RemoteEndPoint,
                                header,
                                StunErrorCodes.ServerError,
                                "Internal server error");
                        }
                        catch { /* Ignore errors sending error response */ }
                    }
                }

            } while (!cancellationToken.IsCancellationRequested);
        }

        private static async Task HandleBindingRequest(UdpClient udpServer, UdpReceiveResult udpReceive, Message req)
        {
            req.PrintDebug();

            // Check for duplicate transaction
            if (_transactionLog.Count > 99)
                _transactionLog.Dequeue();

            var txns = Encoding.UTF8.GetString(req.Header.TransactionId);

            if (_transactionLog.Contains(txns))
                return;

            _transactionLog.Enqueue(txns);

            // Check for unknown comprehension-required attributes
            if (req.Attributes != null)
            {
                var parseResult = MessageAttribute.ParseListWithResult(
                    udpReceive.Buffer.Skip(20).ToArray(),
                    req.Header.TransactionId);

                if (parseResult.HasUnknownComprehensionRequired)
                {
                    await Console.Error.WriteLineAsync(
                        $"Request contains unknown comprehension-required attributes: " +
                        string.Join(", ", parseResult.UnknownComprehensionRequiredTypes.Select(t => $"0x{t:X4}")));

                    await SendUnknownAttributeError(
                        udpServer,
                        udpReceive.RemoteEndPoint,
                        req.Header,
                        parseResult.UnknownComprehensionRequiredTypes);
                    return;
                }
            }

            // Build successful response
            var attributeList = new List<MessageAttribute>
            {
                new MappedAddressAttribute
                {
                    AddressFamily = udpReceive.RemoteEndPoint.AddressFamily,
                    Port = (ushort)udpReceive.RemoteEndPoint.Port,
                    IPAddress = udpReceive.RemoteEndPoint.Address
                },
                new XorMappedAddressAttribute(req.Header.TransactionId)
                {
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

            await Console.Error.WriteLineAsync($"Sending BindingResponse with {attributeList.Count} attributes");
            resp.PrintDebug();

            var respBytes = resp.ToByteArray();
            await udpServer.SendAsync(respBytes, respBytes.Length, udpReceive.RemoteEndPoint);
        }

        /// <summary>
        /// Sends an error response with the specified error code and reason.
        /// </summary>
        private static async Task SendErrorResponse(
            UdpClient udpServer,
            IPEndPoint remoteEndpoint,
            MessageHeader requestHeader,
            int errorCode,
            string? reason = null)
        {
            var errorAttr = reason != null
                ? StunErrorCodes.CreateErrorAttribute(errorCode, reason)
                : StunErrorCodes.CreateErrorAttribute(errorCode);

            var attributeList = new List<MessageAttribute> { errorAttr }.AsReadOnly();

            var resp = new Message
            {
                Header = new MessageHeader
                {
                    Type = MessageType.BindingError,
                    MessageLength = (ushort)attributeList.Sum(a => a.Bytes.Count),
                    MagicCookie = requestHeader.MagicCookie,
                    TransactionId = requestHeader.TransactionId
                },
                Attributes = attributeList
            };

            await Console.Error.WriteLineAsync($"Sending BindingError {errorCode}: {errorAttr.ReasonPhrase}");
            resp.PrintDebug();

            var respBytes = resp.ToByteArray();
            await udpServer.SendAsync(respBytes, respBytes.Length, remoteEndpoint);
        }

        /// <summary>
        /// Sends a 420 Unknown Attribute error response with the list of unknown attribute types.
        /// </summary>
        private static async Task SendUnknownAttributeError(
            UdpClient udpServer,
            IPEndPoint remoteEndpoint,
            MessageHeader requestHeader,
            IEnumerable<ushort> unknownTypes)
        {
            var errorAttr = StunErrorCodes.CreateErrorAttribute(StunErrorCodes.UnknownAttribute);
            var unknownAttr = new UnknownAttributesAttribute(unknownTypes);

            var attributeList = new List<MessageAttribute> { errorAttr, unknownAttr }.AsReadOnly();

            var resp = new Message
            {
                Header = new MessageHeader
                {
                    Type = MessageType.BindingError,
                    MessageLength = (ushort)attributeList.Sum(a => a.Bytes.Count),
                    MagicCookie = requestHeader.MagicCookie,
                    TransactionId = requestHeader.TransactionId
                },
                Attributes = attributeList
            };

            await Console.Error.WriteLineAsync($"Sending BindingError 420 with unknown attributes: {unknownAttr}");
            resp.PrintDebug();

            var respBytes = resp.ToByteArray();
            await udpServer.SendAsync(respBytes, respBytes.Length, remoteEndpoint);
        }
    }
}
