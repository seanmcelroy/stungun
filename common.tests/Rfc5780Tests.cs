using System.Net;
using Xunit;
using stungun.common.client;
using stungun.common.core;

namespace stungun.common.tests
{
    public class Rfc5780Tests
    {
        #region ChangeRequestAttribute Tests

        [Fact]
        public void ChangeRequestAttribute_DefaultValues_AllFalse()
        {
            var attr = new ChangeRequestAttribute();

            Assert.False(attr.ChangeIP);
            Assert.False(attr.ChangePort);
            Assert.Equal(AttributeType.ChangeRequest, attr.Type);
            Assert.Equal(4, attr.AttributeLength);
        }

        [Fact]
        public void ChangeRequestAttribute_SetChangeIP_SetsCorrectBit()
        {
            var attr = new ChangeRequestAttribute { ChangeIP = true };

            Assert.True(attr.ChangeIP);
            Assert.False(attr.ChangePort);

            // Verify wire format: bit 0x04 should be set
            Assert.NotNull(attr.Value);
            Assert.Equal(4, attr.Value.Length);
            Assert.Equal(0x04, attr.Value[3]);
        }

        [Fact]
        public void ChangeRequestAttribute_SetChangePort_SetsCorrectBit()
        {
            var attr = new ChangeRequestAttribute { ChangePort = true };

            Assert.False(attr.ChangeIP);
            Assert.True(attr.ChangePort);

            // Verify wire format: bit 0x02 should be set
            Assert.NotNull(attr.Value);
            Assert.Equal(4, attr.Value.Length);
            Assert.Equal(0x02, attr.Value[3]);
        }

        [Fact]
        public void ChangeRequestAttribute_SetBothFlags_SetsCorrectBits()
        {
            var attr = new ChangeRequestAttribute
            {
                ChangeIP = true,
                ChangePort = true
            };

            Assert.True(attr.ChangeIP);
            Assert.True(attr.ChangePort);

            // Verify wire format: bits 0x04 and 0x02 should be set = 0x06
            Assert.NotNull(attr.Value);
            Assert.Equal(0x06, attr.Value[3]);
        }

        [Fact]
        public void ChangeRequestAttribute_ClearFlags_ClearsCorrectBits()
        {
            var attr = new ChangeRequestAttribute
            {
                ChangeIP = true,
                ChangePort = true
            };

            // Clear ChangeIP
            attr.ChangeIP = false;

            Assert.False(attr.ChangeIP);
            Assert.True(attr.ChangePort);
            Assert.Equal(0x02, attr.Value![3]);

            // Clear ChangePort
            attr.ChangePort = false;

            Assert.False(attr.ChangeIP);
            Assert.False(attr.ChangePort);
            Assert.Equal(0x00, attr.Value[3]);
        }

        [Fact]
        public void ChangeRequestAttribute_RoundTrip_PreservesFlags()
        {
            var original = new ChangeRequestAttribute
            {
                ChangeIP = true,
                ChangePort = true
            };

            var bytes = original.ToByteArray();

            // Parse it back
            var parsed = MessageAttribute.Parse(bytes);
            Assert.Equal(AttributeType.ChangeRequest, parsed.Type);

            var typedParsed = ChangeRequestAttribute.FromGenericAttribute(parsed);
            Assert.True(typedParsed.ChangeIP);
            Assert.True(typedParsed.ChangePort);
        }

        [Fact]
        public void ChangeRequestAttribute_Serialize_CorrectWireFormat()
        {
            var attr = new ChangeRequestAttribute
            {
                ChangeIP = true,
                ChangePort = false
            };

            var bytes = attr.ToByteArray();

            // Type: 0x0003 (CHANGE-REQUEST)
            Assert.Equal(0x00, bytes[0]);
            Assert.Equal(0x03, bytes[1]);

            // Length: 4
            Assert.Equal(0x00, bytes[2]);
            Assert.Equal(0x04, bytes[3]);

            // Value: 0x00000004 (ChangeIP flag)
            Assert.Equal(0x00, bytes[4]);
            Assert.Equal(0x00, bytes[5]);
            Assert.Equal(0x00, bytes[6]);
            Assert.Equal(0x04, bytes[7]);
        }

        #endregion

        #region NatMappingTypeRfc5780 Enum Tests

        [Fact]
        public void NatMappingTypeRfc5780_HasCorrectValues()
        {
            Assert.Equal(0, (int)NatMappingTypeRfc5780.Unknown);
            Assert.Equal(1, (int)NatMappingTypeRfc5780.EndpointIndependent);
            Assert.Equal(2, (int)NatMappingTypeRfc5780.AddressDependent);
            Assert.Equal(3, (int)NatMappingTypeRfc5780.AddressAndPortDependent);
        }

        #endregion

        #region NatFilteringTypeRfc5780 Enum Tests

        [Fact]
        public void NatFilteringTypeRfc5780_HasCorrectValues()
        {
            Assert.Equal(0, (int)NatFilteringTypeRfc5780.Unknown);
            Assert.Equal(1, (int)NatFilteringTypeRfc5780.EndpointIndependent);
            Assert.Equal(2, (int)NatFilteringTypeRfc5780.AddressDependent);
            Assert.Equal(3, (int)NatFilteringTypeRfc5780.AddressAndPortDependent);
        }

        #endregion

        #region AddressAttribute.SetType Tests

        [Fact]
        public void AddressAttribute_SetType_ChangesType()
        {
            var attr = new AddressAttribute
            {
                AddressFamily = System.Net.Sockets.AddressFamily.InterNetwork,
                Port = 3478,
                IPAddress = IPAddress.Parse("192.168.1.1")
            };

            // Initially no type set
            attr.SetType(AttributeType.ResponseOrigin);
            Assert.Equal(AttributeType.ResponseOrigin, attr.Type);

            attr.SetType(AttributeType.OtherAddress);
            Assert.Equal(AttributeType.OtherAddress, attr.Type);
        }

        [Fact]
        public void AddressAttribute_ResponseOrigin_Serializes()
        {
            var attr = new AddressAttribute
            {
                AddressFamily = System.Net.Sockets.AddressFamily.InterNetwork,
                Port = 3478,
                IPAddress = IPAddress.Parse("192.168.1.1")
            };
            attr.SetType(AttributeType.ResponseOrigin);

            var bytes = attr.ToByteArray();

            // Type: 0x802B (RESPONSE-ORIGIN)
            Assert.Equal(0x80, bytes[0]);
            Assert.Equal(0x2B, bytes[1]);
        }

        [Fact]
        public void AddressAttribute_OtherAddress_Serializes()
        {
            var attr = new AddressAttribute
            {
                AddressFamily = System.Net.Sockets.AddressFamily.InterNetwork,
                Port = 3479,
                IPAddress = IPAddress.Parse("10.0.0.1")
            };
            attr.SetType(AttributeType.OtherAddress);

            var bytes = attr.ToByteArray();

            // Type: 0x802C (OTHER-ADDRESS)
            Assert.Equal(0x80, bytes[0]);
            Assert.Equal(0x2C, bytes[1]);
        }

        #endregion

        #region StunServerConfiguration Tests

        [Fact]
        public void StunServerConfiguration_DefaultValues()
        {
            var config = new stungun.common.server.StunServerConfiguration();

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

            var config = new stungun.common.server.StunServerConfiguration
            {
                PrimaryEndpoint = primary,
                AlternateEndpoint = alternate
            };

            Assert.Equal(primary, config.PrimaryEndpoint);
            Assert.Equal(alternate, config.AlternateEndpoint);
        }

        #endregion

        #region DiscoveryClient Tests

        [Fact]
        public void DiscoveryClient_CanBeCreated()
        {
            var client = new DiscoveryClient("stun.example.com", 3478, 5000);

            // Just verify it doesn't throw
            Assert.NotNull(client);
        }

        [Fact]
        public void DiscoveryClient_DefaultParameters()
        {
            // Should not throw with default parameters
            var client = new DiscoveryClient();
            Assert.NotNull(client);
        }

        #endregion
    }
}
