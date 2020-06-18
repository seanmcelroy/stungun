using System;
using System.Collections.Generic;
using System.Linq;

namespace stungun.common.core
{
    public static class MessageUtility
    {
        public static byte[] ToByteArray(this MessageHeader header)
        {
            var ret = new byte[20];
            Array.Copy(BitConverter.GetBytes((ushort)header.Type).Reverse().ToArray(), 0, ret, 0, 2);
            Array.Copy(BitConverter.GetBytes((ushort)header.MessageLength).Reverse().ToArray(), 0, ret, 2, 2);
            Array.Copy(BitConverter.GetBytes(header.MagicCookie).Reverse().ToArray(), 0, ret, 4, 4);
            Array.Copy(header.TransactionId, 0, ret, 8, 12);
            return ret;
        }

        public static byte[] ToByteArray(this MessageAttribute attribute)
        {
            if (attribute == null)
                throw new ArgumentNullException(nameof(attribute));
            if (attribute.Value == null || attribute.Value.Length == 0)
                throw new ArgumentNullException(nameof(attribute.Value));
            if (attribute.AttributeLength != attribute.Value.Length)
                throw new ArgumentException($"Attribute {attribute.Type} length {attribute.AttributeLength} did not match attribute value's actual byte array length of {attribute.Value.Length}");
            if ((attribute.Value.Length + 4) % 4 != 0)
                throw new ArgumentOutOfRangeException($"Attributes must break on a 32-boundary, but type {attribute.Type} was {attribute.Value} bytes long", nameof(attribute));

            var ret = new byte[4 + attribute.Value.Length];
            Array.Copy(BitConverter.GetBytes((ushort)attribute.Type), 0, ret, 0, 2);
            Array.Copy(BitConverter.GetBytes((ushort)attribute.Value.Length), 0, ret, 2, 2);
            Array.Copy(attribute.Value, 0, ret, 4, attribute.Value.Length);
            return ret;
        }

        public static byte[] ToByteArray(this Message message)
        {
            var attrBytes = new List<byte[]>();
            if (message.Attributes != null)
                foreach (var attr in message.Attributes)
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
