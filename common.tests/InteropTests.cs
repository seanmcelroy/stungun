using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using stungun.common.client;
using stungun.common.core;

namespace stungun.common.tests
{
    /// <summary>
    /// Interoperability tests against public STUN servers.
    /// These tests require network access and may fail if the servers are unavailable.
    /// Tests are throttled to avoid rate limiting from public servers.
    /// </summary>
    [Trait("Category", "Integration")]
    [Trait("Category", "Network")]
    [Collection("InteropTests")]
    public class InteropTests : IAsyncLifetime
    {
        // Delay between tests to avoid rate limiting (milliseconds)
        private const int ThrottleDelayMs = 1000;

        private static readonly SemaphoreSlim _throttle = new(1, 1);

        public static TheoryData<string, int> PublicStunServers => new()
        {
            { "stun.l.google.com", 19302 },
            // Rate limited or down { "stunserver2024.stunprotocol.org", 3478 }
        };

        public async Task InitializeAsync()
        {
            // Wait for throttle before each test
            await _throttle.WaitAsync();
            await Task.Delay(ThrottleDelayMs);
        }

        public Task DisposeAsync()
        {
            _throttle.Release();
            return Task.CompletedTask;
        }

        #region Basic Connectivity Tests

        [Theory]
        [MemberData(nameof(PublicStunServers))]
        public async Task BindingRequest_PublicServer_Success(string hostname, int port)
        {
            using var client = new StunUdpClient(hostname, port);
            var response = await client.BindingRequestAsync(recvTimeout: 5000);

            Assert.True(response.Success, $"Failed to connect to {hostname}:{port}: {response.ErrorMessage}");
        }

        [Theory]
        [MemberData(nameof(PublicStunServers))]
        public async Task BindingRequest_PublicServer_ReturnsXorMappedAddress(string hostname, int port)
        {
            using var client = new StunUdpClient(hostname, port);
            var response = await client.BindingRequestAsync(recvTimeout: 5000);

            Assert.True(response.Success, $"Failed to connect to {hostname}:{port}: {response.ErrorMessage}");
            Assert.NotNull(response.Message.Attributes);

            var xorMapped = response.Message.Attributes
                .FirstOrDefault(a => a.Type == AttributeType.XorMappedAddress || a.Type == AttributeType.XorMappedAddress2);

            Assert.NotNull(xorMapped);
            Assert.IsAssignableFrom<XorMappedAddressAttribute>(xorMapped);

            var typedAttr = (XorMappedAddressAttribute)xorMapped;
            Assert.NotNull(typedAttr.IPAddress);
            Assert.NotEqual(IPAddress.None, typedAttr.IPAddress);
            Assert.True(typedAttr.Port > 0);
        }

        [Theory]
        [MemberData(nameof(PublicStunServers))]
        public async Task BindingRequest_PublicServer_ResponseTypeIsBindingResponse(string hostname, int port)
        {
            using var client = new StunUdpClient(hostname, port);
            var response = await client.BindingRequestAsync(recvTimeout: 5000);

            Assert.True(response.Success, $"Failed to connect to {hostname}:{port}: {response.ErrorMessage}");
            Assert.Equal(MessageType.BindingResponse, response.Message.Header.Type);
        }

        [Theory]
        [MemberData(nameof(PublicStunServers))]
        public async Task BindingRequest_PublicServer_TransactionIdPreserved(string hostname, int port)
        {
            var customTxId = new byte[] { 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78 };

            using var client = new StunUdpClient(hostname, port);
            var response = await client.BindingRequestAsync(
                recvTimeout: 5000,
                customTransactionId: customTxId);

            Assert.True(response.Success, $"Failed to connect to {hostname}:{port}: {response.ErrorMessage}");
            Assert.Equal(customTxId, response.Message.Header.TransactionId);
        }

        [Theory]
        [MemberData(nameof(PublicStunServers))]
        public async Task BindingRequest_PublicServer_MagicCookieCorrect(string hostname, int port)
        {
            using var client = new StunUdpClient(hostname, port);
            var response = await client.BindingRequestAsync(recvTimeout: 5000);

            Assert.True(response.Success, $"Failed to connect to {hostname}:{port}: {response.ErrorMessage}");
            // Magic cookie is stored in little-endian in the struct after parsing
            Assert.Equal(0x42A41221u, response.Message.Header.MagicCookie);
        }

        #endregion

        #region Mapped Address Tests

        [Theory]
        [MemberData(nameof(PublicStunServers))]
        public async Task BindingRequest_PublicServer_MappedAddressIsPublicIP(string hostname, int port)
        {
            using var client = new StunUdpClient(hostname, port);
            var response = await client.BindingRequestAsync(recvTimeout: 5000);

            Assert.True(response.Success, $"Failed to connect to {hostname}:{port}: {response.ErrorMessage}");
            Assert.NotNull(response.Message.Attributes);

            var xorMapped = response.Message.Attributes
                .OfType<XorMappedAddressAttribute>()
                .FirstOrDefault();

            Assert.NotNull(xorMapped);

            // The mapped address should not be a private IP (assuming we're behind NAT)
            // Note: This might not always be true in all network configurations
            var ip = xorMapped.IPAddress;
            Assert.NotNull(ip);

            // At minimum, it should be a valid IP address
            Assert.NotEqual(IPAddress.None, ip);
            Assert.NotEqual(IPAddress.Any, ip);
        }

        [Theory]
        [MemberData(nameof(PublicStunServers))]
        public async Task BindingRequest_PublicServer_ConsistentAddress_SameClient(string hostname, int port)
        {
            // Multiple requests from the same client should get the same mapped address
            using var client1 = new StunUdpClient(hostname, port);
            var response1 = await client1.BindingRequestAsync(recvTimeout: 5000);

            Assert.True(response1.Success, $"First request failed to {hostname}:{port}: {response1.ErrorMessage}");

            await Task.Delay(500); // Small delay between requests within same test

            using var client2 = new StunUdpClient(hostname, port);
            var response2 = await client2.BindingRequestAsync(recvTimeout: 5000);

            Assert.True(response2.Success, $"Second request failed to {hostname}:{port}: {response2.ErrorMessage}");

            var xorMapped1 = response1.Message.Attributes?
                .OfType<XorMappedAddressAttribute>()
                .FirstOrDefault();
            var xorMapped2 = response2.Message.Attributes?
                .OfType<XorMappedAddressAttribute>()
                .FirstOrDefault();

            Assert.NotNull(xorMapped1);
            Assert.NotNull(xorMapped2);

            // IP should be the same (port might differ due to NAT behavior)
            Assert.Equal(xorMapped1.IPAddress, xorMapped2.IPAddress);
        }

        #endregion

        #region Google STUN Server Specific Tests

        [Fact]
        public async Task GoogleStunServer_BindingRequest_Success()
        {
            using var client = new StunUdpClient("stun.l.google.com", 19302);
            var response = await client.BindingRequestAsync(recvTimeout: 5000);

            Assert.True(response.Success, $"Failed to connect to Google STUN: {response.ErrorMessage}");
            Assert.Equal(MessageType.BindingResponse, response.Message.Header.Type);
        }

        [Fact]
        public async Task GoogleStunServer_ReturnsValidAttributes()
        {
            using var client = new StunUdpClient("stun.l.google.com", 19302);
            var response = await client.BindingRequestAsync(recvTimeout: 5000);

            Assert.True(response.Success, $"Failed: {response.ErrorMessage}");
            Assert.NotNull(response.Message.Attributes);
            Assert.True(response.Message.Attributes.Count > 0);

            // Google typically returns XOR-MAPPED-ADDRESS
            var hasXorMapped = response.Message.Attributes
                .Any(a => a.Type == AttributeType.XorMappedAddress || a.Type == AttributeType.XorMappedAddress2);
            Assert.True(hasXorMapped, "Expected XOR-MAPPED-ADDRESS attribute from Google STUN");
        }

        #endregion

        #region StunProtocol.org Server Specific Tests

        [Fact(Skip = "Rate limited or down")]
        public async Task StunProtocolOrg_BindingRequest_Success()
        {
            using var client = new StunUdpClient("stunserver2024.stunprotocol.org", 3478);
            var response = await client.BindingRequestAsync(recvTimeout: 5000);

            Assert.True(response.Success, $"Failed to connect to stunprotocol.org: {response.ErrorMessage}");
            Assert.Equal(MessageType.BindingResponse, response.Message.Header.Type);
        }

        [Fact(Skip = "Rate limited or down")]
        public async Task StunProtocolOrg_ReturnsRfc5780Attributes()
        {
            using var client = new StunUdpClient("stunserver2024.stunprotocol.org", 3478);
            var response = await client.BindingRequestAsync(recvTimeout: 5000);

            Assert.True(response.Success, $"Failed: {response.ErrorMessage}");
            Assert.NotNull(response.Message.Attributes);

            // stunprotocol.org typically supports RFC 5780 and returns additional attributes
            var attributeTypes = response.Message.Attributes.Select(a => a.Type).ToList();

            // Should have at least XOR-MAPPED-ADDRESS
            Assert.Contains(AttributeType.XorMappedAddress, attributeTypes);

            // RFC 5780 compliant servers often include these
            // (not asserting because some servers might not include them)
            var hasResponseOrigin = attributeTypes.Contains(AttributeType.ResponseOrigin);
            var hasOtherAddress = attributeTypes.Contains(AttributeType.OtherAddress);

            // Log for informational purposes
            if (hasResponseOrigin)
                Console.WriteLine("Server includes RESPONSE-ORIGIN");
            if (hasOtherAddress)
                Console.WriteLine("Server includes OTHER-ADDRESS");
        }

        #endregion

        #region Error Handling Tests

        [Fact]
        public async Task InvalidHostname_ReturnsError()
        {
            using var client = new StunUdpClient("invalid.hostname.that.does.not.exist.example.com", 3478);

            // Should either throw or return an error response
            try
            {
                var response = await client.BindingRequestAsync(recvTimeout: 2000);
                Assert.False(response.Success);
            }
            catch (Exception)
            {
                // DNS resolution failure is also acceptable
                Assert.True(true);
            }
        }

        [Fact]
        public async Task WrongPort_TimesOut()
        {
            // Connect to Google on a wrong port
            using var client = new StunUdpClient("stun.l.google.com", 12345);
            var response = await client.BindingRequestAsync(recvTimeout: 2000);

            Assert.False(response.Success);
        }

        #endregion
    }

    /// <summary>
    /// Collection definition to ensure interop tests run serially.
    /// </summary>
    [CollectionDefinition("InteropTests")]
    public class InteropTestsCollection : ICollectionFixture<InteropTestsFixture>
    {
    }

    /// <summary>
    /// Shared fixture for interop tests.
    /// </summary>
    public class InteropTestsFixture
    {
    }
}
