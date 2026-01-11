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
                if (Value == null || Value.Length < 4)
                    return System.Net.Sockets.AddressFamily.Unspecified;

                var af = Value[1];
                return af switch
                {
                    0x01 => System.Net.Sockets.AddressFamily.InterNetwork,
                    0x02 => System.Net.Sockets.AddressFamily.InterNetworkV6,
                    _ => System.Net.Sockets.AddressFamily.Unknown,
                };
            }
            set
            {
                if (Value == null)
                {
                    Value = new byte[8];
                    AttributeLength = (ushort)Value.Length;
                }

                switch (value)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        Value[1] = 0x01;
                        break;
                    case System.Net.Sockets.AddressFamily.InterNetworkV6:
                        Value[1] = 0x02;
                        break;
                    default:
                        Value[1] = 0x00;
                        break;
                }
            }
        }

        public virtual ushort Port
        {
            get => Value == null ? (ushort)0 : BitConverter.ToUInt16(new byte[] { Value[3], Value[2] });
            set
            {
                if (Value == null)
                {
                    Value = new byte[8];
                    AttributeLength = (ushort)Value.Length;
                }

                Array.Copy(BitConverter.GetBytes(MessageUtility.SwapBytes(value)), 0, Value, 2, 2);
            }
        }

        public virtual IPAddress IPAddress
        {
            get
            {
                switch (AddressFamily)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        {
                            var addrBytes = ((ReadOnlySpan<byte>)Value).Slice(4, 4);
                            return new IPAddress(addrBytes);
                        }
                    case System.Net.Sockets.AddressFamily.InterNetworkV6:
                        {
                            var addrBytes = ((ReadOnlySpan<byte>)Value).Slice(4, 16);
                            return new IPAddress(addrBytes);
                        }
                    default:
                        throw new InvalidOperationException("Unsupported address family has no IP address");
                }
            }

            set
            {
                ArgumentNullException.ThrowIfNull(value);

                if (Value == null)
                    switch (value.AddressFamily)
                    {
                        case System.Net.Sockets.AddressFamily.InterNetworkV6:
                            Value = new byte[20];
                            Array.Copy(value.GetAddressBytes(), 0, Value, 4, 20);
                            break;
                        case System.Net.Sockets.AddressFamily.InterNetwork:
                            Value = new byte[8];
                            Array.Copy(value.GetAddressBytes(), 0, Value, 4, 4);
                            break;

                        default:
                            Value = new byte[8];
                            break;
                    }
                else
                {
                    switch (value.AddressFamily)
                    {
                        case System.Net.Sockets.AddressFamily.InterNetworkV6:
                            if (Value.Length < 20)
                            {
                                var newVal = new byte[20];
                                Array.Copy(Value, newVal, Value.Length);
                                Value = newVal;
                            }
                            Array.Copy(value.GetAddressBytes(), 0, Value, 4, 20);
                            break;
                        case System.Net.Sockets.AddressFamily.InterNetwork:
                            if (Value.Length > 8)
                            {
                                var newVal = new byte[8];
                                Array.Copy(Value, newVal, 4);
                                Value = newVal;
                            }
                            Array.Copy(value.GetAddressBytes(), 0, Value, 4, 4);
                            break;
                        default:
                            Value = new byte[8];
                            break;
                    }
                }

                AttributeLength = (ushort)Value.Length;
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

        /// <summary>
        /// Sets the attribute type. Used for creating RESPONSE-ORIGIN, OTHER-ADDRESS, etc.
        /// </summary>
        public void SetType(AttributeType type)
        {
            Type = type;
        }

        public override string ToString() => $"{IPAddress}:{Port}";
    }
}
