using System;
using System.Net;

namespace stungun.common.core
{
    public class AddressAttribute : MessageAttribute
    {
        public virtual System.Net.Sockets.AddressFamily AddressFamily
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
            set
            {
                if (this.Value == null)
                {
                    this.Value = new byte[8];
                    this.AttributeLength = (ushort)this.Value.Length;
                }

                switch (value)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        this.Value[1] = 0x01;
                        break;
                    case System.Net.Sockets.AddressFamily.InterNetworkV6:
                        this.Value[1] = 0x02;
                        break;
                    default:
                        this.Value[1] = 0x00;
                        break;
                }
            }
        }

        public virtual ushort Port
        {
            get => BitConverter.ToUInt16(new byte[] { this.Value[3], this.Value[2] });
            set
            {
                if (this.Value == null)
                {
                    this.Value = new byte[8];
                    this.AttributeLength = (ushort)this.Value.Length;
                }

                Array.Copy(BitConverter.GetBytes(MessageUtility.SwapBytes(value)), 0, this.Value, 2, 2);
            }
        }

        public virtual IPAddress IPAddress
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

            set
            {
                if (value == null)
                    throw new ArgumentNullException(nameof(value));

                if (this.Value == null)
                    switch (value.AddressFamily)
                    {
                        case System.Net.Sockets.AddressFamily.InterNetworkV6:
                            this.Value = new byte[20];
                            Array.Copy(value.GetAddressBytes(), 0, this.Value, 4, 20);
                            break;
                        case System.Net.Sockets.AddressFamily.InterNetwork:
                            this.Value = new byte[8];
                            Array.Copy(value.GetAddressBytes(), 0, this.Value, 4, 4);
                            break;

                        default:
                            this.Value = new byte[8];
                            break;
                    }
                else
                {
                    switch (value.AddressFamily)
                    {
                        case System.Net.Sockets.AddressFamily.InterNetworkV6:
                            if (this.Value.Length < 20)
                            {
                                var newVal = new byte[20];
                                Array.Copy(this.Value, newVal, this.Value.Length);
                                this.Value = newVal;
                            }
                            Array.Copy(value.GetAddressBytes(), 0, this.Value, 4, 20);
                            break;
                        case System.Net.Sockets.AddressFamily.InterNetwork:
                            if (this.Value.Length > 8)
                            {
                                var newVal = new byte[8];
                                Array.Copy(this.Value, newVal, 4);
                                this.Value = newVal;
                            }
                            Array.Copy(value.GetAddressBytes(), 0, this.Value, 4, 4);
                            break;
                        default:
                            this.Value = new byte[8];
                            break;
                    }
                }

                this.AttributeLength = (ushort)this.Value.Length;
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
