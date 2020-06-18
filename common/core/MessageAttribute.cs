using System;
using System.Collections.Generic;
using System.Linq;

namespace stungun.common.core
{
    public class MessageAttribute
    {
        public AttributeType Type { get; protected set; }
        public ushort AttributeLength { get; protected set; }
        public byte[]? Value { get; protected set; }

        public static MessageAttribute Parse(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 4)
                throw new ArgumentOutOfRangeException(nameof(bytes), "Message attributes must be at least 4 bytes long");

            var bytesSpan = (ReadOnlySpan<byte>)bytes;

            var aType = BitConverter.ToUInt16(new byte[] { bytes[1], bytes[0] });
            var aLen = BitConverter.ToUInt16(new byte[] { bytes[3], bytes[2] });
            if (bytesSpan.Length < aLen - 4)
                throw new InvalidOperationException("Insufficient attribute length");
            var aVal = bytesSpan.Slice(4, aLen).ToArray();

            if (!Enum.IsDefined(typeof(AttributeType), aType))
            {
                if (aType >= 0x8000 && aType <= 0xFFFF)
                {
                    Console.Error.WriteLine($"Skipping unknown comprehension-optional value: {aType:x2}");
                    return new MessageAttribute
                    {
                        Type = AttributeType.Unknown,
                        AttributeLength = aLen,
                    };
                }
                throw new InvalidOperationException($"Unknown comprehension-require attribute {aType:x2}");
            }

            var ret = new MessageAttribute
            {
                Type = (AttributeType)aType,
                AttributeLength = aLen,
                Value = aVal
            };

            return ret;
        }

        public static IEnumerable<MessageAttribute> ParseList(byte[] bytes, byte[] transactionId)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 4)
                throw new ArgumentOutOfRangeException(nameof(bytes), "Message attributes must be at least 4 bytes long");

            var attrOffset = 0;
            do
            {
                var nextAttribute = Parse(bytes.Skip(attrOffset).ToArray());
                if (nextAttribute != null && nextAttribute.Type != AttributeType.Unknown)
                {
                    switch (nextAttribute.Type)
                    {
                        case AttributeType.MappedAddress:
                            yield return MappedAddressAttribute.FromGenericAttribute(nextAttribute);
                            break;

                        case AttributeType.XorMappedAddress:
                        case AttributeType.XorMappedAddress2:
                            yield return XorMappedAddressAttribute.FromGenericAttribute(nextAttribute, transactionId);
                            break;

                        case AttributeType.ReservedResponseAddress:
                        case AttributeType.ReservedSourceAddress:
                        case AttributeType.ReservedChangedAddress:
                        case AttributeType.AlternateServer:
                        case AttributeType.ResponseOrigin:
                        case AttributeType.OtherAddress:
                            yield return AddressAttribute.FromGenericAttribute(nextAttribute);
                            break;

                        default:
                            yield return nextAttribute;
                            break;
                    }
                }
                attrOffset += (4 + nextAttribute?.AttributeLength ?? 0);
            } while (attrOffset < bytes.Length);
        }
    }
}
