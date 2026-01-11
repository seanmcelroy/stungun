using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using stungun.common.core;

namespace stungun.common.client
{
    /// <summary>
    /// Client for NAT type discovery using STUN.
    /// Supports both RFC 3489 (legacy) and RFC 5780 (modern) discovery methods.
    /// </summary>
    public class DiscoveryClient
    {
        private readonly string _stunHostname;
        private readonly int _stunPort;
        private readonly int _timeout;

        /// <summary>
        /// Creates a new discovery client.
        /// </summary>
        /// <param name="stunHostname">STUN server hostname. Must support RFC 5780 for full discovery.</param>
        /// <param name="stunPort">STUN server port (default 3478).</param>
        /// <param name="timeout">Request timeout in milliseconds (default 3000).</param>
        public DiscoveryClient(
            string stunHostname = "stunserver2024.stunprotocol.org",
            int stunPort = 3478,
            int timeout = 3000)
        {
            _stunHostname = stunHostname;
            _stunPort = stunPort;
            _timeout = timeout;
        }

        /// <summary>
        /// Performs NAT discovery using the RFC 3489 algorithm.
        /// This is a legacy method that classifies NAT into cone types.
        /// </summary>
        public async Task<NatTypeRfc3489> DiscoverUdpRfc3489Async(CancellationToken cancellationToken = default)
        {
            MessageResponse test1;
            using (var stunUdpClient = new StunUdpClient(_stunHostname, _stunPort))
            {
                test1 = await stunUdpClient.BindingRequestAsync(
                    recvTimeout: _timeout,
                    cancellationToken: cancellationToken);
                if (!test1.Success)
                    return NatTypeRfc3489.UdpBlocked;
            }

            var test1Ip = GetMappedAddress(test1.Message)?.IPAddress;
            if (test1Ip == null)
                return NatTypeRfc3489.Unknown;

            // Is test1 the same IP as our local address?
            var ipSame = test1Ip.Equals(test1.LocalEndpoint.Address);

            MessageResponse test2;
            using (var stunUdpClient = new StunUdpClient(_stunHostname, _stunPort))
            {
                test2 = await stunUdpClient.BindingRequestAsync(
                    attributes:
                    [
                        new ChangeRequestAttribute { ChangeIP = true, ChangePort = true }
                    ],
                    recvTimeout: _timeout,
                    cancellationToken: cancellationToken);
            }

            if (ipSame)
            {
                if (test2.Success)
                    return NatTypeRfc3489.OpenInternet;
                else
                    return NatTypeRfc3489.SymmetricUdpFirewall;
            }

            if (test2.Success)
                return NatTypeRfc3489.FullCone;

            // Test for symmetric NAT by making another request and comparing mapped addresses
            using (var stunUdpClient = new StunUdpClient(_stunHostname, _stunPort))
            {
                var test1b = await stunUdpClient.BindingRequestAsync(
                    recvTimeout: _timeout,
                    cancellationToken: cancellationToken);
                if (!test1b.Success)
                    return NatTypeRfc3489.Unknown;

                var test1IpB = GetMappedAddress(test1b.Message)?.IPAddress;
                if (test1IpB == null)
                    return NatTypeRfc3489.Unknown;

                var ipSameB = test1IpB.Equals(test1b.LocalEndpoint.Address);
                if (!ipSameB)
                    return NatTypeRfc3489.SymmetricNat;
            }

            // Test for port restricted vs restricted cone
            using (var stunUdpClient = new StunUdpClient(_stunHostname, _stunPort))
            {
                var test3 = await stunUdpClient.BindingRequestAsync(
                    attributes:
                    [
                        new ChangeRequestAttribute { ChangeIP = false, ChangePort = true }
                    ],
                    recvTimeout: _timeout,
                    cancellationToken: cancellationToken);

                if (test3.Success)
                    return NatTypeRfc3489.RestrictedCone;
            }

            return NatTypeRfc3489.PortRestrictedCone;
        }

        /// <summary>
        /// Performs NAT behavior discovery using the RFC 5780 algorithm.
        /// This method separately characterizes mapping and filtering behavior.
        /// Requires a STUN server that supports RFC 5780 (provides OTHER-ADDRESS attribute).
        /// </summary>
        public async Task<(NatMappingTypeRfc5780 mapping, NatFilteringTypeRfc5780 filtering)> DiscoverUdpRfc5780Async(
            CancellationToken cancellationToken = default)
        {
            // First, get the primary response which should include OTHER-ADDRESS
            var primaryResult = await SendBindingRequestAsync(_stunHostname, _stunPort, cancellationToken);
            if (!primaryResult.Success)
            {
                return (NatMappingTypeRfc5780.Unknown, NatFilteringTypeRfc5780.Unknown);
            }

            var primaryMapped = GetMappedAddress(primaryResult.Message);
            var otherAddress = GetOtherAddress(primaryResult.Message);

            if (primaryMapped == null)
            {
                return (NatMappingTypeRfc5780.Unknown, NatFilteringTypeRfc5780.Unknown);
            }

            // Detect mapping behavior
            var mappingType = await DetectMappingBehaviorAsync(
                primaryMapped,
                otherAddress,
                cancellationToken);

            // Detect filtering behavior
            var filteringType = await DetectFilteringBehaviorAsync(cancellationToken);

            return (mappingType, filteringType);
        }

        /// <summary>
        /// Detects NAT mapping behavior per RFC 5780 Section 4.3.
        /// </summary>
        private async Task<NatMappingTypeRfc5780> DetectMappingBehaviorAsync(
            AddressAttribute primaryMapped,
            AddressAttribute? otherAddress,
            CancellationToken cancellationToken)
        {
            var primaryExternalEndpoint = new IPEndPoint(primaryMapped.IPAddress, primaryMapped.Port);

            // If server doesn't provide OTHER-ADDRESS, we can't complete the test
            if (otherAddress == null)
            {
                // Fall back: try to determine if we're behind NAT at all
                // by comparing mapped address to local address
                return NatMappingTypeRfc5780.Unknown;
            }

            // Test I: Send to alternate IP address
            // This tests if the NAT uses the same mapping for different destination IPs
            var alternateIp = otherAddress.IPAddress.ToString();
            var alternatePort = _stunPort; // Use same port, different IP

            var test2Result = await SendBindingRequestAsync(alternateIp, alternatePort, cancellationToken);
            if (!test2Result.Success)
            {
                // Can't reach alternate address - might be filtered or server doesn't support it
                return NatMappingTypeRfc5780.Unknown;
            }

            var test2Mapped = GetMappedAddress(test2Result.Message);
            if (test2Mapped == null)
            {
                return NatMappingTypeRfc5780.Unknown;
            }

            var test2ExternalEndpoint = new IPEndPoint(test2Mapped.IPAddress, test2Mapped.Port);

            // Compare mappings
            if (primaryExternalEndpoint.Equals(test2ExternalEndpoint))
            {
                // Same mapping for different destination IPs = Endpoint-Independent Mapping
                return NatMappingTypeRfc5780.EndpointIndependent;
            }

            if (primaryExternalEndpoint.Address.Equals(test2ExternalEndpoint.Address))
            {
                // Same IP but different port = Address-Dependent Mapping
                return NatMappingTypeRfc5780.AddressDependent;
            }

            // Test II: Send to alternate IP and port
            // This confirms Address-and-Port-Dependent if the mapping differs
            var test3Result = await SendBindingRequestAsync(
                alternateIp,
                otherAddress.Port,
                cancellationToken);

            if (!test3Result.Success)
            {
                // If same IP gives different mapping, it's at least Address-Dependent
                return NatMappingTypeRfc5780.AddressDependent;
            }

            var test3Mapped = GetMappedAddress(test3Result.Message);
            if (test3Mapped == null)
            {
                return NatMappingTypeRfc5780.AddressDependent;
            }

            var test3ExternalEndpoint = new IPEndPoint(test3Mapped.IPAddress, test3Mapped.Port);

            if (!test2ExternalEndpoint.Equals(test3ExternalEndpoint))
            {
                // Different port on same IP gives different mapping
                return NatMappingTypeRfc5780.AddressAndPortDependent;
            }

            // Same mapping for different ports on same IP = Address-Dependent
            return NatMappingTypeRfc5780.AddressDependent;
        }

        /// <summary>
        /// Detects NAT filtering behavior per RFC 5780 Section 4.4.
        /// </summary>
        private async Task<NatFilteringTypeRfc5780> DetectFilteringBehaviorAsync(
            CancellationToken cancellationToken)
        {
            // Test I: Request response from alternate IP and port
            using (var client = new StunUdpClient(_stunHostname, _stunPort))
            {
                var test1 = await client.BindingRequestAsync(
                    attributes:
                    [
                        new ChangeRequestAttribute { ChangeIP = true, ChangePort = true }
                    ],
                    recvTimeout: _timeout,
                    cancellationToken: cancellationToken);

                if (test1.Success)
                {
                    // Received response from different IP and port
                    // = Endpoint-Independent Filtering
                    return NatFilteringTypeRfc5780.EndpointIndependent;
                }
            }

            // Test II: Request response from same IP, alternate port
            using (var client = new StunUdpClient(_stunHostname, _stunPort))
            {
                var test2 = await client.BindingRequestAsync(
                    attributes:
                    [
                        new ChangeRequestAttribute { ChangeIP = false, ChangePort = true }
                    ],
                    recvTimeout: _timeout,
                    cancellationToken: cancellationToken);

                if (test2.Success)
                {
                    // Received response from same IP but different port
                    // = Address-Dependent Filtering
                    return NatFilteringTypeRfc5780.AddressDependent;
                }
            }

            // No response from alternate port = Address-and-Port-Dependent Filtering
            return NatFilteringTypeRfc5780.AddressAndPortDependent;
        }

        /// <summary>
        /// Sends a binding request to the specified server.
        /// </summary>
        private async Task<MessageResponse> SendBindingRequestAsync(
            string hostname,
            int port,
            CancellationToken cancellationToken)
        {
            using var client = new StunUdpClient(hostname, port);
            return await client.BindingRequestAsync(
                recvTimeout: _timeout,
                cancellationToken: cancellationToken);
        }

        /// <summary>
        /// Extracts the mapped address (XOR-MAPPED-ADDRESS preferred, MAPPED-ADDRESS fallback).
        /// </summary>
        private static AddressAttribute? GetMappedAddress(Message message)
        {
            if (message.Attributes == null)
                return null;

            // Prefer XOR-MAPPED-ADDRESS per RFC 5389
            var xorMapped = message.Attributes
                .Where(a => a.Type == AttributeType.XorMappedAddress || a.Type == AttributeType.XorMappedAddress2)
                .OfType<XorMappedAddressAttribute>()
                .FirstOrDefault();

            if (xorMapped != null)
                return xorMapped;

            // Fall back to MAPPED-ADDRESS
            return message.Attributes
                .Where(a => a.Type == AttributeType.MappedAddress)
                .OfType<MappedAddressAttribute>()
                .FirstOrDefault();
        }

        /// <summary>
        /// Extracts the OTHER-ADDRESS attribute if present.
        /// This attribute indicates an alternate server address for RFC 5780 tests.
        /// </summary>
        private static AddressAttribute? GetOtherAddress(Message message)
        {
            if (message.Attributes == null)
                return null;

            return message.Attributes
                .Where(a => a.Type == AttributeType.OtherAddress)
                .OfType<AddressAttribute>()
                .FirstOrDefault();
        }

        /// <summary>
        /// Extracts the RESPONSE-ORIGIN attribute if present.
        /// This attribute indicates which server address sent the response.
        /// </summary>
        private static AddressAttribute? GetResponseOrigin(Message message)
        {
            if (message.Attributes == null)
                return null;

            return message.Attributes
                .Where(a => a.Type == AttributeType.ResponseOrigin)
                .OfType<AddressAttribute>()
                .FirstOrDefault();
        }
    }
}
