using System;
using System.Buffers;
using System.Linq;
using System.Net;

namespace stungun.common.core
{
    public sealed class XorMappedAddressAttribute : AddressAttribute
    {
        private readonly byte[] transactionId;

        public override System.Net.Sockets.AddressFamily AddressFamily
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

        public override ushort Port
        {
            get
            {
                var xPort = BitConverter.ToUInt16(new byte[] { this.Value[3], this.Value[2] });
                var port = (ushort)(xPort ^ (ushort)0x2112);
                return port;
            }
            set
            {
                var xPort = (ushort)(value ^ (ushort)0x2112);
                var bytes = BitConverter.GetBytes(xPort);
                this.Value[2] = bytes[1];
                this.Value[3] = bytes[0];
            }
        }

        public override IPAddress IPAddress
        {
            get
            {
                switch (this.AddressFamily)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        {
                            var addrBytes = ((ReadOnlySpan<byte>)this!.Value).Slice(4, 4).ToArray().Reverse().ToArray();
                            var addr = BitConverter.ToUInt32(addrBytes) ^ (uint)0x2112A442;
                            return new IPAddress(MessageUtility.SwapBytes(addr));
                        }
                    case System.Net.Sockets.AddressFamily.InterNetworkV6:
                        {
                            var l1 = ((ReadOnlySpan<byte>)this.Value).Slice(4, 4).ToArray().Reverse().ToArray();
                            var addr1 = BitConverter.ToUInt32(l1) ^ (uint)0x2112A442;
                            var b1 = MessageUtility.SwapBytes(addr1);

                            var l2 = ((ReadOnlySpan<byte>)this.Value).Slice(8, 4).ToArray().Reverse().ToArray();
                            var t2 = ((ReadOnlySpan<byte>)this.transactionId).Slice(0, 4);
                            var addr2 = BitConverter.ToUInt32(l2) ^ BitConverter.ToUInt32(t2);
                            var b2 = MessageUtility.SwapBytes(addr2);

                            var l3 = ((ReadOnlySpan<byte>)this.Value).Slice(12, 4).ToArray().Reverse().ToArray();
                            var t3 = ((ReadOnlySpan<byte>)this.transactionId).Slice(4, 4);
                            var addr3 = BitConverter.ToUInt32(l3) ^ BitConverter.ToUInt32(t3);
                            var b3 = MessageUtility.SwapBytes(addr3);

                            var l4 = ((ReadOnlySpan<byte>)this.Value).Slice(16, 4).ToArray().Reverse().ToArray();
                            var t4 = ((ReadOnlySpan<byte>)this.transactionId).Slice(8, 4);
                            var addr4 = BitConverter.ToUInt32(l4) ^ BitConverter.ToUInt32(t4);
                            var b4 = MessageUtility.SwapBytes(addr4);

                            var addrBytes = new ArrayBufferWriter<byte>();
                            addrBytes.Write(BitConverter.GetBytes(b1));
                            addrBytes.Write(BitConverter.GetBytes(b2));
                            addrBytes.Write(BitConverter.GetBytes(b3));
                            addrBytes.Write(BitConverter.GetBytes(b4));
                            return new IPAddress(addrBytes.WrittenSpan);
                        }
                    default:
                        throw new InvalidOperationException("Unsupported address family has no IP address");
                }
            }

            set
            {
                var addrBytes = value.GetAddressBytes().Reverse().ToArray();
                switch (value.AddressFamily)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        {
                            var addr = MessageUtility.SwapBytes(BitConverter.ToUInt32(addrBytes) ^ (uint)0x2112A442);
                            var xAddrBytes = BitConverter.GetBytes(addr);
                            Array.Copy(xAddrBytes, 0, this.Value, 4, 4);
                            break;
                        }
                    case System.Net.Sockets.AddressFamily.InterNetworkV6:
                        {
                            var l1 = ((ReadOnlySpan<byte>)addrBytes).Slice(0, 4).ToArray().Reverse().ToArray();
                            var xAddr1 = BitConverter.ToUInt32(l1) ^ (uint)0x2112A442;
                            var xb1 = MessageUtility.SwapBytes(xAddr1);

                            var l2 = ((ReadOnlySpan<byte>)addrBytes).Slice(4, 4).ToArray().Reverse().ToArray();
                            var t2 = ((ReadOnlySpan<byte>)this.transactionId).Slice(0, 4);
                            var xAddr2 = BitConverter.ToUInt32(l2) ^ BitConverter.ToUInt32(t2);
                            var xb2 = MessageUtility.SwapBytes(xAddr2);

                            var l3 = ((ReadOnlySpan<byte>)addrBytes).Slice(8, 4).ToArray().Reverse().ToArray();
                            var t3 = ((ReadOnlySpan<byte>)this.transactionId).Slice(4, 4);
                            var xAddr3 = BitConverter.ToUInt32(l3) ^ BitConverter.ToUInt32(t3);
                            var xb3 = MessageUtility.SwapBytes(xAddr3);

                            var l4 = ((ReadOnlySpan<byte>)addrBytes).Slice(12, 4).ToArray().Reverse().ToArray();
                            var t4 = ((ReadOnlySpan<byte>)this.transactionId).Slice(8, 4);
                            var xAddr4 = BitConverter.ToUInt32(l4) ^ BitConverter.ToUInt32(t4);
                            var xb4 = MessageUtility.SwapBytes(xAddr4);

                            Array.Copy(BitConverter.GetBytes(xb1), 0, this.Value, 4, 4);
                            Array.Copy(BitConverter.GetBytes(xb2), 0, this.Value, 8, 4);
                            Array.Copy(BitConverter.GetBytes(xb3), 0, this.Value, 12, 4);
                            Array.Copy(BitConverter.GetBytes(xb4), 0, this.Value, 16, 4);

                            break;
                        }
                    default:
                        throw new InvalidOperationException("Unsupported address family has no IP address");
                }

            }
        }

        public XorMappedAddressAttribute(byte[] transactionId)
        {
            this.transactionId = transactionId;
            this.Type = AttributeType.XorMappedAddress;
        }

        public static XorMappedAddressAttribute FromGenericAttribute(MessageAttribute attr, byte[] transactionId)
        {
            return new XorMappedAddressAttribute(transactionId)
            {
                Type = attr.Type,
                AttributeLength = attr.AttributeLength,
                Value = attr.Value
            };
        }

        public override string ToString() => $"{IPAddress}:{Port}";
    }
}
