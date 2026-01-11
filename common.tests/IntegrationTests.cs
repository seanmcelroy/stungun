using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using stungun.common.client;
using stungun.common.core;
using stungun.common.server;

namespace stungun.common.tests
{
    public class IntegrationTests : IDisposable
    {
        private static int _portCounter = 13478;
        private readonly int _testPort;

        public IntegrationTests()
        {
            // Use unique port for each test to avoid conflicts
            _testPort = Interlocked.Increment(ref _portCounter);
        }

        public void Dispose()
        {
            // Cleanup if needed
        }

        private static async Task StopServerSafelyAsync(StunUdpServer server, CancellationTokenSource cts)
        {
            cts.Cancel();
            // Give the server task time to process cancellation
            await Task.Delay(50);
            try
            {
                server.Stop();
            }
            catch
            {
                // Ignore disposal errors
            }
        }

        #region UDP Client/Server Integration Tests

        [Fact]
        public async Task UdpClient_LocalServer_BindingRequest_Success()
        {
            var config = new StunServerConfiguration
            {
                PrimaryEndpoint = new IPEndPoint(IPAddress.Loopback, _testPort),
                IncludeResponseOrigin = true,
                IncludeOtherAddress = false
            };

            using var cts = new CancellationTokenSource();
            var server = new StunUdpServer(new[] { config.PrimaryEndpoint }, config);
            server.Start((ushort)_testPort, cts.Token);

            // Give server time to start
            await Task.Delay(100);

            using var client = new StunUdpClient("127.0.0.1", _testPort);
            var response = await client.BindingRequestAsync(recvTimeout: 2000);

            await StopServerSafelyAsync(server, cts);

            Assert.True(response.Success, response.ErrorMessage);
            Assert.NotNull(response.Message.Attributes);
            Assert.True(response.Message.Attributes.Count >= 2); // At least MAPPED-ADDRESS and XOR-MAPPED-ADDRESS
        }

        [Fact]
        public async Task UdpClient_LocalServer_ReceivesMappedAddress()
        {
            var config = new StunServerConfiguration
            {
                PrimaryEndpoint = new IPEndPoint(IPAddress.Loopback, _testPort),
                IncludeResponseOrigin = true,
                IncludeOtherAddress = false
            };

            using var cts = new CancellationTokenSource();
            var server = new StunUdpServer(new[] { config.PrimaryEndpoint }, config);
            server.Start((ushort)_testPort, cts.Token);

            await Task.Delay(100);

            using var client = new StunUdpClient("127.0.0.1", _testPort);
            var response = await client.BindingRequestAsync(recvTimeout: 2000);

            await StopServerSafelyAsync(server, cts);

            Assert.True(response.Success, response.ErrorMessage);
            Assert.NotNull(response.Message.Attributes);

            var mappedAddress = response.Message.Attributes
                .FirstOrDefault(a => a.Type == AttributeType.MappedAddress);

            Assert.NotNull(mappedAddress);
            Assert.IsType<MappedAddressAttribute>(mappedAddress);

            var typedMapped = (MappedAddressAttribute)mappedAddress;
            Assert.NotNull(typedMapped.IPAddress);
            Assert.True(typedMapped.Port > 0);
        }

        [Fact]
        public async Task UdpClient_LocalServer_ReceivesXorMappedAddress()
        {
            var config = new StunServerConfiguration
            {
                PrimaryEndpoint = new IPEndPoint(IPAddress.Loopback, _testPort),
                IncludeResponseOrigin = true,
                IncludeOtherAddress = false
            };

            using var cts = new CancellationTokenSource();
            var server = new StunUdpServer(new[] { config.PrimaryEndpoint }, config);
            server.Start((ushort)_testPort, cts.Token);

            await Task.Delay(100);

            using var client = new StunUdpClient("127.0.0.1", _testPort);
            var response = await client.BindingRequestAsync(recvTimeout: 2000);

            await StopServerSafelyAsync(server, cts);

            Assert.True(response.Success, response.ErrorMessage);
            Assert.NotNull(response.Message.Attributes);

            var xorMappedAddress = response.Message.Attributes
                .FirstOrDefault(a => a.Type == AttributeType.XorMappedAddress);

            Assert.NotNull(xorMappedAddress);
            Assert.IsType<XorMappedAddressAttribute>(xorMappedAddress);

            var typedXorMapped = (XorMappedAddressAttribute)xorMappedAddress;
            Assert.NotNull(typedXorMapped.IPAddress);
            Assert.True(typedXorMapped.Port > 0);
        }

        [Fact]
        public async Task UdpClient_LocalServer_MappedAndXorMappedMatch()
        {
            var config = new StunServerConfiguration
            {
                PrimaryEndpoint = new IPEndPoint(IPAddress.Loopback, _testPort),
                IncludeResponseOrigin = true,
                IncludeOtherAddress = false
            };

            using var cts = new CancellationTokenSource();
            var server = new StunUdpServer(new[] { config.PrimaryEndpoint }, config);
            server.Start((ushort)_testPort, cts.Token);

            await Task.Delay(100);

            using var client = new StunUdpClient("127.0.0.1", _testPort);
            var response = await client.BindingRequestAsync(recvTimeout: 2000);

            await StopServerSafelyAsync(server, cts);

            Assert.True(response.Success, response.ErrorMessage);
            Assert.NotNull(response.Message.Attributes);

            var mappedAddress = response.Message.Attributes
                .OfType<MappedAddressAttribute>()
                .FirstOrDefault();
            var xorMappedAddress = response.Message.Attributes
                .OfType<XorMappedAddressAttribute>()
                .FirstOrDefault();

            Assert.NotNull(mappedAddress);
            Assert.NotNull(xorMappedAddress);

            // Both should report the same address
            Assert.Equal(mappedAddress.IPAddress, xorMappedAddress.IPAddress);
            Assert.Equal(mappedAddress.Port, xorMappedAddress.Port);
        }

        [Fact]
        public async Task UdpClient_LocalServer_ResponseOriginIncluded()
        {
            var config = new StunServerConfiguration
            {
                PrimaryEndpoint = new IPEndPoint(IPAddress.Loopback, _testPort),
                IncludeResponseOrigin = true,
                IncludeOtherAddress = false
            };

            using var cts = new CancellationTokenSource();
            var server = new StunUdpServer(new[] { config.PrimaryEndpoint }, config);
            server.Start((ushort)_testPort, cts.Token);

            await Task.Delay(100);

            using var client = new StunUdpClient("127.0.0.1", _testPort);
            var response = await client.BindingRequestAsync(recvTimeout: 2000);

            await StopServerSafelyAsync(server, cts);

            Assert.True(response.Success, response.ErrorMessage);
            Assert.NotNull(response.Message.Attributes);

            var responseOrigin = response.Message.Attributes
                .FirstOrDefault(a => a.Type == AttributeType.ResponseOrigin);

            Assert.NotNull(responseOrigin);
        }

        [Fact]
        public async Task UdpClient_LocalServer_OtherAddressIncludedWhenConfigured()
        {
            var config = new StunServerConfiguration
            {
                PrimaryEndpoint = new IPEndPoint(IPAddress.Loopback, _testPort),
                AlternateEndpoint = new IPEndPoint(IPAddress.Parse("192.168.1.100"), _testPort + 1),
                IncludeResponseOrigin = true,
                IncludeOtherAddress = true
            };

            using var cts = new CancellationTokenSource();
            var server = new StunUdpServer(new[] { config.PrimaryEndpoint }, config);
            server.Start((ushort)_testPort, cts.Token);

            await Task.Delay(100);

            using var client = new StunUdpClient("127.0.0.1", _testPort);
            var response = await client.BindingRequestAsync(recvTimeout: 2000);

            await StopServerSafelyAsync(server, cts);

            Assert.True(response.Success, response.ErrorMessage);
            Assert.NotNull(response.Message.Attributes);

            var otherAddress = response.Message.Attributes
                .FirstOrDefault(a => a.Type == AttributeType.OtherAddress);

            Assert.NotNull(otherAddress);
        }

        [Fact]
        public async Task UdpClient_LocalServer_TransactionIdPreserved()
        {
            var config = new StunServerConfiguration
            {
                PrimaryEndpoint = new IPEndPoint(IPAddress.Loopback, _testPort),
                IncludeResponseOrigin = true,
                IncludeOtherAddress = false
            };

            using var cts = new CancellationTokenSource();
            var server = new StunUdpServer(new[] { config.PrimaryEndpoint }, config);
            server.Start((ushort)_testPort, cts.Token);

            await Task.Delay(100);

            var customTxId = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };

            using var client = new StunUdpClient("127.0.0.1", _testPort);
            var response = await client.BindingRequestAsync(
                recvTimeout: 2000,
                customTransactionId: customTxId);

            await StopServerSafelyAsync(server, cts);

            Assert.True(response.Success, response.ErrorMessage);
            Assert.Equal(customTxId, response.Message.Header.TransactionId);
        }

        [Fact]
        public async Task UdpClient_LocalServer_ResponseTypeIsBindingResponse()
        {
            var config = new StunServerConfiguration
            {
                PrimaryEndpoint = new IPEndPoint(IPAddress.Loopback, _testPort),
                IncludeResponseOrigin = true,
                IncludeOtherAddress = false
            };

            using var cts = new CancellationTokenSource();
            var server = new StunUdpServer(new[] { config.PrimaryEndpoint }, config);
            server.Start((ushort)_testPort, cts.Token);

            await Task.Delay(100);

            using var client = new StunUdpClient("127.0.0.1", _testPort);
            var response = await client.BindingRequestAsync(recvTimeout: 2000);

            await StopServerSafelyAsync(server, cts);

            Assert.True(response.Success, response.ErrorMessage);
            Assert.Equal(MessageType.BindingResponse, response.Message.Header.Type);
        }

        [Fact]
        public async Task UdpClient_LocalServer_MagicCookiePreserved()
        {
            var config = new StunServerConfiguration
            {
                PrimaryEndpoint = new IPEndPoint(IPAddress.Loopback, _testPort),
                IncludeResponseOrigin = true,
                IncludeOtherAddress = false
            };

            using var cts = new CancellationTokenSource();
            var server = new StunUdpServer(new[] { config.PrimaryEndpoint }, config);
            server.Start((ushort)_testPort, cts.Token);

            await Task.Delay(100);

            using var client = new StunUdpClient("127.0.0.1", _testPort);
            var response = await client.BindingRequestAsync(recvTimeout: 2000);

            await StopServerSafelyAsync(server, cts);

            Assert.True(response.Success, response.ErrorMessage);
            // Magic cookie is stored in little-endian in the struct
            Assert.Equal(0x42A41221u, response.Message.Header.MagicCookie);
        }

        #endregion

        #region Client Timeout Tests

        [Fact]
        public async Task UdpClient_NoServer_FailsGracefully()
        {
            // Connect to a port with no server
            using var client = new StunUdpClient("127.0.0.1", _testPort);

            try
            {
                var response = await client.BindingRequestAsync(recvTimeout: 500);
                // Should not succeed
                Assert.False(response.Success);
            }
            catch (System.Net.Sockets.SocketException)
            {
                // Connection refused is acceptable on Linux when no server is listening
                Assert.True(true);
            }
        }

        #endregion

        #region Server Configuration Tests

        [Fact]
        public void StunServerConfiguration_DefaultValues()
        {
            var config = new StunServerConfiguration();

            Assert.Null(config.PrimaryEndpoint);
            Assert.Null(config.AlternateEndpoint);
            Assert.True(config.IncludeResponseOrigin);
            Assert.True(config.IncludeOtherAddress);
        }

        [Fact]
        public void StunServerConfiguration_CanSetEndpoints()
        {
            var primary = new IPEndPoint(IPAddress.Parse("192.168.1.1"), 3478);
            var alternate = new IPEndPoint(IPAddress.Parse("192.168.1.2"), 3479);

            var config = new StunServerConfiguration
            {
                PrimaryEndpoint = primary,
                AlternateEndpoint = alternate
            };

            Assert.Equal(primary, config.PrimaryEndpoint);
            Assert.Equal(alternate, config.AlternateEndpoint);
        }

        #endregion

        #region CHANGE-REQUEST Integration Tests

        [Fact]
        public async Task UdpClient_LocalServer_ChangeRequestAttributeAccepted()
        {
            var config = new StunServerConfiguration
            {
                PrimaryEndpoint = new IPEndPoint(IPAddress.Loopback, _testPort),
                IncludeResponseOrigin = true,
                IncludeOtherAddress = false
            };

            using var cts = new CancellationTokenSource();
            var server = new StunUdpServer(new[] { config.PrimaryEndpoint }, config);
            server.Start((ushort)_testPort, cts.Token);

            await Task.Delay(100);

            // Send a request with CHANGE-REQUEST attribute
            var changeRequest = new ChangeRequestAttribute
            {
                ChangeIP = false,
                ChangePort = true
            };

            using var client = new StunUdpClient("127.0.0.1", _testPort);
            var response = await client.BindingRequestAsync(
                attributes: new[] { changeRequest },
                recvTimeout: 2000);

            await StopServerSafelyAsync(server, cts);

            // Server should accept the request (even if it can't fulfill the change request)
            Assert.True(response.Success, response.ErrorMessage);
            Assert.Equal(MessageType.BindingResponse, response.Message.Header.Type);
        }

        #endregion
    }
}
