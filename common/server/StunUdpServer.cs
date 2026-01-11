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
    /// <summary>
    /// Configuration for the STUN UDP server.
    /// </summary>
    public class StunServerConfiguration
    {
        /// <summary>
        /// The primary endpoint this server listens on.
        /// Used for RESPONSE-ORIGIN attribute.
        /// </summary>
        public IPEndPoint? PrimaryEndpoint { get; set; }

        /// <summary>
        /// An alternate endpoint (different IP and/or port) for RFC 5780 support.
        /// If set, the server will include OTHER-ADDRESS in responses.
        /// </summary>
        public IPEndPoint? AlternateEndpoint { get; set; }

        /// <summary>
        /// Whether to include RESPONSE-ORIGIN attribute in responses.
        /// Default is true for RFC 5780 compliance.
        /// </summary>
        public bool IncludeResponseOrigin { get; set; } = true;

        /// <summary>
        /// Whether to include OTHER-ADDRESS attribute in responses when alternate endpoint is configured.
        /// Default is true for RFC 5780 compliance.
        /// </summary>
        public bool IncludeOtherAddress { get; set; } = true;
    }

    public class StunUdpServer : IDisposable
    {
        private static readonly Queue<string> _transactionLog = new Queue<string>(100);

        private bool _disposed = false;

        private UdpClient? UdpServer { get; set; }
        private Task? ServerLoop { get; set; }

        /// <summary>
        /// Server configuration for RFC 5780 support.
        /// </summary>
        public StunServerConfiguration Configuration { get; }

        /// <summary>
        /// The endpoints this server is configured to use.
        /// </summary>
        public IReadOnlyCollection<IPEndPoint> Endpoints { get; set; }

        public StunUdpServer(IEnumerable<IPEndPoint> endpoints)
            : this(endpoints, new StunServerConfiguration())
        {
        }

        public StunUdpServer(IEnumerable<IPEndPoint> endpoints, StunServerConfiguration configuration)
        {
            ArgumentNullException.ThrowIfNull(endpoints);
            ArgumentNullException.ThrowIfNull(configuration);

            Endpoints = endpoints.ToList().AsReadOnly();
            Configuration = configuration;
        }

        ~StunUdpServer() => Dispose(false);

        public void Start(ushort port, CancellationToken cancellationToken = default)
        {
            ServerLoop?.Dispose();
            UdpServer?.Dispose();

            UdpServer = new UdpClient(port);

            // Set the primary endpoint if not already configured
            if (Configuration.PrimaryEndpoint == null && UdpServer.Client.LocalEndPoint is IPEndPoint localEp)
            {
                // Try to get a non-loopback address
                var addresses = Dns.GetHostAddresses(Dns.GetHostName())
                    .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a))
                    .ToList();

                if (addresses.Count > 0)
                {
                    Configuration.PrimaryEndpoint = new IPEndPoint(addresses[0], port);
                }
                else
                {
                    Configuration.PrimaryEndpoint = new IPEndPoint(IPAddress.Any, port);
                }
            }

            ServerLoop = Task.Run(async () => await ProcessingLoop(UdpServer, Configuration, cancellationToken));
        }

        public void Stop()
        {
            ServerLoop?.Dispose();
            ServerLoop = null;
            UdpServer?.Dispose();
            UdpServer = null;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                ServerLoop?.Dispose();
                ServerLoop = null;
                UdpServer?.Dispose();
                UdpServer = null;
            }

            _disposed = true;
        }

        private static async Task ProcessingLoop(
            UdpClient udpServer,
            StunServerConfiguration config,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(udpServer);

            do
            {
                UdpReceiveResult udpReceive = default;
                try
                {
                    udpReceive = await udpServer.ReceiveAsync(cancellationToken);

                    // Validate minimum message length
                    if (udpReceive.Buffer.Length < 20)
                    {
                        await Console.Error.WriteLineAsync($"Received malformed message: too short ({udpReceive.Buffer.Length} bytes)");
                        continue;
                    }

                    var req = Message.Parse(udpReceive.Buffer);

                    switch (req.Header.Type)
                    {
                        case MessageType.BindingRequest:
                            await HandleBindingRequest(udpServer, udpReceive, req, config);
                            break;

                        case MessageType.BindingError:
                            req.PrintDebug();
                            break;

                        default:
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
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (ArgumentOutOfRangeException ex)
                {
                    await Console.Error.WriteLineAsync($"Bad request: {ex.Message}");
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

        private static async Task HandleBindingRequest(
            UdpClient udpServer,
            UdpReceiveResult udpReceive,
            Message req,
            StunServerConfiguration config)
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

            // Build successful response with RFC 5780 attributes
            var attributeList = new List<MessageAttribute>
            {
                // MAPPED-ADDRESS (legacy, for backward compatibility)
                new MappedAddressAttribute
                {
                    AddressFamily = udpReceive.RemoteEndPoint.AddressFamily,
                    Port = (ushort)udpReceive.RemoteEndPoint.Port,
                    IPAddress = udpReceive.RemoteEndPoint.Address
                },
                // XOR-MAPPED-ADDRESS (preferred per RFC 5389)
                new XorMappedAddressAttribute(req.Header.TransactionId)
                {
                    AddressFamily = udpReceive.RemoteEndPoint.AddressFamily,
                    Port = (ushort)udpReceive.RemoteEndPoint.Port,
                    IPAddress = udpReceive.RemoteEndPoint.Address
                }
            };

            // Add RESPONSE-ORIGIN for RFC 5780 (indicates which address sent the response)
            if (config.IncludeResponseOrigin && config.PrimaryEndpoint != null)
            {
                var responseOrigin = new AddressAttribute
                {
                    AddressFamily = config.PrimaryEndpoint.AddressFamily,
                    Port = (ushort)config.PrimaryEndpoint.Port,
                    IPAddress = config.PrimaryEndpoint.Address
                };
                responseOrigin.SetType(AttributeType.ResponseOrigin);
                attributeList.Add(responseOrigin);
            }

            // Add OTHER-ADDRESS for RFC 5780 (indicates alternate server address)
            if (config.IncludeOtherAddress && config.AlternateEndpoint != null)
            {
                var otherAddress = new AddressAttribute
                {
                    AddressFamily = config.AlternateEndpoint.AddressFamily,
                    Port = (ushort)config.AlternateEndpoint.Port,
                    IPAddress = config.AlternateEndpoint.Address
                };
                otherAddress.SetType(AttributeType.OtherAddress);
                attributeList.Add(otherAddress);
            }

            var readOnlyAttributes = attributeList.AsReadOnly();

            var resp = new Message
            {
                Header = new MessageHeader
                {
                    Type = MessageType.BindingResponse,
                    MessageLength = (ushort)readOnlyAttributes.Sum(a => a.Bytes.Count),
                    MagicCookie = req.Header.MagicCookie,
                    TransactionId = req.Header.TransactionId
                },
                Attributes = readOnlyAttributes
            };

            await Console.Error.WriteLineAsync($"Sending BindingResponse with {readOnlyAttributes.Count} attributes");
            resp.PrintDebug();

            var respBytes = resp.ToByteArray();
            await udpServer.SendAsync(respBytes, respBytes.Length, udpReceive.RemoteEndPoint);
        }

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
