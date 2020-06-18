using System;
using System.Buffers;
using System.Linq;
using System.Net;

namespace stungun.common.core
{
    public class XorMappedAddressAttribute : MessageAttribute
    {
        private byte[] transactionId;

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

        public ushort Port
        {
            get
            {
                var xPort = BitConverter.ToUInt16(new byte[] { this.Value[3], this.Value[2] });
                var port = xPort ^ (ushort)0x2112;

                //Console.WriteLine($"#5: {SwapBytes((ushort)(BitConverter.ToUInt16(new byte[] { this.Value[3], this.Value[2] }) ^ (ushort)0x2112))}");
                return (ushort)SwapBytes((ushort)port);
            }
        }

        public IPAddress IPAddress
        {
            get
            {
                switch (this.AddressFamily)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        {
                            var addrBytes = ((ReadOnlySpan<byte>)this!.Value).Slice(4, 4).ToArray().Reverse().ToArray();
                            var addr = BitConverter.ToUInt32(addrBytes) ^ (uint)0x2112A442;
                            return new IPAddress(SwapBytes(addr));
                        }
                    case System.Net.Sockets.AddressFamily.InterNetworkV6:
                        {
                            var l1 = ((ReadOnlySpan<byte>)this.Value).Slice(4, 4).ToArray().Reverse().ToArray();
                            var addr1 = BitConverter.ToUInt32(l1) ^ (uint)0x2112A442;
                            var b1 = SwapBytes(addr1);

                            var l2 = ((ReadOnlySpan<byte>)this.Value).Slice(8, 4).ToArray().Reverse().ToArray();
                            var t2 = ((ReadOnlySpan<byte>)this.transactionId).Slice(0,4);
                            var addr2 = BitConverter.ToUInt32(l2) ^ BitConverter.ToUInt32(t2);
                            var b2 = SwapBytes(addr2);

                            var l3 = ((ReadOnlySpan<byte>)this.Value).Slice(12, 4).ToArray().Reverse().ToArray();
                            var t3 = ((ReadOnlySpan<byte>)this.transactionId).Slice(4,4);
                            var addr3 = BitConverter.ToUInt32(l3) ^ BitConverter.ToUInt32(t3);
                            var b3 = SwapBytes(addr3);

                            var l4 = ((ReadOnlySpan<byte>)this.Value).Slice(16, 4).ToArray().Reverse().ToArray();
                            var t4 = ((ReadOnlySpan<byte>)this.transactionId).Slice(8,4);
                            var addr4 = BitConverter.ToUInt32(l4) ^ BitConverter.ToUInt32(t4);
                            var b4 = SwapBytes(addr4);

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
        }

        public static XorMappedAddressAttribute FromGenericAttribute(MessageAttribute attr, byte[] transactionId)
        {
            return new XorMappedAddressAttribute
            {
                Type = attr.Type,
                AttributeLength = attr.AttributeLength,
                Value = attr.Value
            };
        }

        public static ushort SwapBytes(ushort x) => (ushort)((ushort)((x & 0xff) << 8) | ((x >> 8) & 0xff));

        public uint SwapBytes(uint x) => ((x & 0x000000ff) << 24) +
                   ((x & 0x0000ff00) << 8) +
                   ((x & 0x00ff0000) >> 8) +
                   ((x & 0xff000000) >> 24);

        public override string ToString() => $"{IPAddress}:{Port}";
    }
}
