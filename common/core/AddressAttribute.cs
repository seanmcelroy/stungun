using System;
using System.Net;

namespace stungun.common.core
{
    public class AddressAttribute : MessageAttribute
    {
        public System.Net.Sockets.AddressFamily AddressFamily
        {
            get
            {
                if (this.Value == null || this.Value.Length < 4)
                    return System.Net.Sockets.AddressFamily.Unspecified;

                var af = this.Value[1];
                switch (af)
                {
                    case 0x01:
                        return System.Net.Sockets.AddressFamily.InterNetwork;
                    case 0x02:
                        return System.Net.Sockets.AddressFamily.InterNetworkV6;
                    default:
                        return System.Net.Sockets.AddressFamily.Unknown;
                }
            }
        }

        public ushort Port { get => BitConverter.ToUInt16(this.Value, 2); }

        public IPAddress IPAddress
        {
            get
            {
                switch (this.AddressFamily)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        {                        
                            var addrBytes = ((ReadOnlySpan<byte>)this.Value).Slice(4, 4);
                            return new IPAddress(addrBytes);
                        }
                    case System.Net.Sockets.AddressFamily.InterNetworkV6:
                        {
                            var addrBytes = ((ReadOnlySpan<byte>)this.Value).Slice(4, 16);
                            return new IPAddress(addrBytes);
                        }
                    default:
                        throw new InvalidOperationException("Unsupported address family has no IP address");
                }
            }
        }

        public static AddressAttribute FromGenericAttribute(MessageAttribute attr)
        {
            return new AddressAttribute
            {
                Type = attr.Type,
                AttributeLength = attr.AttributeLength,
                Value = attr.Value
            };
        }

        public override string ToString() => $"{IPAddress}:{Port}";
    }
}
