using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using stungun.common.core;

namespace stungun.common.client
{
    public class DiscoveryClient
    {
        private readonly string stunHostname;
        private readonly int stunPort;

        public DiscoveryClient(
            string stunHostname = "127.0.0.1", //  "stun.stunprotocol.org",
            int stunPort = 3478)
        {
            this.stunHostname = stunHostname;
            this.stunPort = stunPort;
        }

        public async Task<NatTypeRfc3489> DiscoverUdpRfc3489Async(CancellationToken cancellationToken = default(CancellationToken))
        {
            MessageResponse test1;
            using (var stunUdpClient = new StunUdpClient(stunHostname, stunPort))
            {
                test1 = await stunUdpClient.BindingRequestAsync(cancellationToken: cancellationToken);
                if (!test1.Success)
                    return NatTypeRfc3489.UdpBlocked;
            }

            var test1Ip =
                   test1.Message.Attributes.Where(a => a.Type == AttributeType.XorMappedAddress).Cast<XorMappedAddressAttribute>().FirstOrDefault()?.IPAddress
                ?? test1.Message.Attributes.Where(a => a.Type == AttributeType.MappedAddress).Cast<MappedAddressAttribute>().FirstOrDefault()?.IPAddress;

            if (test1Ip == null)
                return NatTypeRfc3489.Unknown;

            // Is test1 the same IP?
            var ipSame = test1Ip.Equals(test1.LocalEndpoint.Address);

            MessageResponse test2;
            using (var stunUdpClient = new StunUdpClient(stunHostname, stunPort))
            {
                test2 = await stunUdpClient.BindingRequestAsync(
                    new List<MessageAttribute> {
                        new ChangeRequestAttribute {
                            ChangeIP = true,
                            ChangePort = true
                        }
                    },
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

            using (var stunUdpClient = new StunUdpClient(stunHostname, stunPort))
            {
                var test1b = await stunUdpClient.BindingRequestAsync(cancellationToken: cancellationToken);
                if (!test1b.Success)
                    return NatTypeRfc3489.Unknown;

                var test1IpB =
                   test1b.Message.Attributes.Where(a => a.Type == AttributeType.XorMappedAddress).Cast<XorMappedAddressAttribute>().FirstOrDefault()?.IPAddress
                ?? test1b.Message.Attributes.Where(a => a.Type == AttributeType.MappedAddress).Cast<MappedAddressAttribute>().FirstOrDefault()?.IPAddress;

                if (test1IpB == null)
                    return NatTypeRfc3489.Unknown;

                var ipSameB = test1IpB.Equals(test1b.LocalEndpoint.Address);
                if (!ipSameB)
                    return NatTypeRfc3489.SymmetricNat;
            }

            using (var stunUdpClient = new StunUdpClient(stunHostname, stunPort))
            {
                var test3 = await stunUdpClient.BindingRequestAsync(
                                new List<MessageAttribute> {
                                    new ChangeRequestAttribute {
                                        ChangeIP = false,
                                        ChangePort = true
                                    }
                                },
                                cancellationToken: cancellationToken);

                if (test3.Success)
                    return NatTypeRfc3489.RestrictedCone;
            }

            return NatTypeRfc3489.PortRestrictedCone;
        }

        public async Task<(NatMappingTypeRfc5780 mapping, NatFilteringTypeRfc5780 filtering)> DiscoverUdpRfc5780Async(CancellationToken cancellationToken = default(CancellationToken))
        {
            return (mapping: NatMappingTypeRfc5780.Unknown, filtering: NatFilteringTypeRfc5780.Unknown);
        }
    }
}
