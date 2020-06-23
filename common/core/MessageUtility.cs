using System;
using System.Collections.Generic;
using System.Linq;

namespace stungun.common.core
{
    public static class MessageUtility
    {

        public static ushort SwapBytes(this ushort x) => (ushort)((ushort)((x & 0xff) << 8) | ((x >> 8) & 0xff));

        public static uint SwapBytes(this uint x) => ((x & 0x000000ff) << 24) +
                   ((x & 0x0000ff00) << 8) +
                   ((x & 0x00ff0000) >> 8) +
                   ((x & 0xff000000) >> 24);

        public static byte[] ToByteArray(this MessageHeader header)
        {
            var ret = new byte[20];
            Array.Copy(BitConverter.GetBytes((ushort)header.Type).Reverse().ToArray(), 0, ret, 0, 2);
            Array.Copy(BitConverter.GetBytes((ushort)header.MessageLength).Reverse().ToArray(), 0, ret, 2, 2);
            Array.Copy(BitConverter.GetBytes(header.MagicCookie).Reverse().ToArray(), 0, ret, 4, 4);
            Array.Copy(header.TransactionId, 0, ret, 8, 12);
            return ret;
        }

        public static byte[] ToByteArray(this Message message)
        {
            var attrBytes = new List<byte[]>();
            if (message.Attributes != null)
                foreach (var attr in message.Attributes)
                    if (attr != null)
                        attrBytes.Add(attr.ToByteArray());

            var ret = new byte[20 + attrBytes.Sum(ab => ab.Length)];

            // Message header
            Array.Copy(BitConverter.GetBytes((ushort)message.Header.Type).Reverse().ToArray(), 0, ret, 0, 2);
            Array.Copy(BitConverter.GetBytes((ushort)message.Header.MessageLength).Reverse().ToArray(), 0, ret, 2, 2);
            Array.Copy(BitConverter.GetBytes(0x2112A442).Reverse().ToArray(), 0, ret, 4, 4);
            Array.Copy(message.Header.TransactionId, 0, ret, 8, 12);

            var idx = 20;
            foreach (var ab in attrBytes)
            {
                Array.Copy(ab, 0, ret, idx, ab.Length);
                idx += ab.Length;
            }

            return ret;
        }
    }
}
