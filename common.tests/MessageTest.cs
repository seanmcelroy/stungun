using System;
using System.Linq;
using Xunit;
using stungun.common.core;

namespace stungun.common.tests
{
    public class MessageTest
    {
        [Fact]
        public void ParseBindingRequestAndRepackageNoAttributes()
        {
            var ba = ByteUtility.StringToByteArray("000100002112a442ba2cd7344e99232f23f396ce");
            var msg = Message.Parse(ba);

            Assert.NotEqual(default(Message), msg);
            Assert.NotEqual(default(MessageHeader), msg.Header);
            Assert.Null(msg.Attributes);

            Assert.Equal(MessageType.BindingRequest, msg.Header.Type);
            Assert.Equal((ushort)0, msg.Header.MessageLength);
            Assert.Equal((uint)0x42A41221, msg.Header.MagicCookie);

            var ba2 = MessageUtility.ToByteArray(msg);
            Assert.NotNull(ba2);
            Assert.Equal(ba.Length, ba2.Length);
            Assert.Equal(ba, ba2);
        }

        [Fact]
        public void ParseBindingResponseAndRepackage()
        {
            var ba = ByteUtility.StringToByteArray("010100302112a442ba2cd7344e99232f23f396ce000100080001d2d968bb4fb2802b000800010d9612bfdf0c802c000800010d9712db6e12002000080001f3cb49a9ebf0");
            var msg = Message.Parse(ba);

            Assert.NotEqual(default(Message), msg);
            Assert.NotEqual(default(MessageHeader), msg.Header);
            Assert.NotNull(msg.Attributes);
            Assert.Equal(4, msg.Attributes.Count);

            Assert.Equal(MessageType.BindingResponse, msg.Header.Type);
            Assert.Equal((ushort)48, msg.Header.MessageLength);
            Assert.Equal((uint)0x42A41221, msg.Header.MagicCookie);

            {
                var a1 = msg.Attributes[0];
                Assert.NotNull(a1);
                Assert.Equal(AttributeType.MappedAddress, a1.Type);
                Assert.Equal(typeof(MappedAddressAttribute), a1.GetType());
                var a1t = (MappedAddressAttribute)a1;
                Assert.Equal(System.Net.Sockets.AddressFamily.InterNetwork, a1t.AddressFamily);

                Assert.Equal((ushort)53977, a1t.Port);
                a1t.Port = (ushort)53977;
                Assert.Equal((ushort)53977, a1t.Port);

                Assert.Equal(System.Net.IPAddress.Parse("104.187.79.178"), a1t.IPAddress);
                a1t.IPAddress = System.Net.IPAddress.Parse("104.187.79.178");
                Assert.Equal(System.Net.IPAddress.Parse("104.187.79.178"), a1t.IPAddress);
            }

            {
                var a2 = msg.Attributes[1];
                Assert.NotNull(a2);
                Assert.Equal(AttributeType.ResponseOrigin, a2.Type);
                Assert.Equal(typeof(AddressAttribute), a2.GetType());
                var a2t = (AddressAttribute)a2;
                Assert.Equal(System.Net.Sockets.AddressFamily.InterNetwork, a2t.AddressFamily);
                Assert.Equal((ushort)3478, a2t.Port);
                Assert.Equal(System.Net.IPAddress.Parse("18.191.223.12"), a2t.IPAddress);
            }

            {
                var a3 = msg.Attributes[2];
                Assert.NotNull(a3);
                Assert.Equal(AttributeType.OtherAddress, a3.Type);
                Assert.Equal(typeof(AddressAttribute), a3.GetType());
                var a3t = (AddressAttribute)a3;
                Assert.Equal(System.Net.Sockets.AddressFamily.InterNetwork, a3t.AddressFamily);
                Assert.Equal((ushort)3479, a3t.Port);
                Assert.Equal(System.Net.IPAddress.Parse("18.219.110.18"), a3t.IPAddress);
            }

            {
                var a4 = msg.Attributes[3];
                Assert.NotNull(a4);
                Assert.Equal(AttributeType.XorMappedAddress, a4.Type);
                Assert.Equal(typeof(XorMappedAddressAttribute), a4.GetType());
                var a4t = (XorMappedAddressAttribute)a4;

                Assert.Equal(System.Net.Sockets.AddressFamily.InterNetwork, a4t.AddressFamily);
                a4t.AddressFamily = System.Net.Sockets.AddressFamily.InterNetwork;
                Assert.Equal(System.Net.Sockets.AddressFamily.InterNetwork, a4t.AddressFamily);

                Assert.Equal((ushort)53977, a4t.Port);
                a4t.Port = (ushort)53977;
                Assert.Equal((ushort)53977, a4t.Port);

                Assert.Equal(System.Net.IPAddress.Parse("104.187.79.178"), a4t.IPAddress);
                a4t.IPAddress = System.Net.IPAddress.Parse("104.187.79.178");
                Assert.Equal(System.Net.IPAddress.Parse("104.187.79.178"), a4t.IPAddress);
            }

            var ba2 = MessageUtility.ToByteArray(msg);
            Assert.NotNull(ba2);
            // Console.WriteLine(ba2.Select(b => $"{b:x2}").Aggregate((c, n) => c + n));
            Assert.Equal(ba.Length, ba2.Length);
            Assert.Equal(ba, ba2);
        }
    }
}
