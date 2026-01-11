using System;
using System.Collections.Generic;
using System.Linq;

namespace stungun.common.core
{
    public class MessageAttribute
    {
        private byte[]? _byteArray;

        public AttributeType Type { get; protected set; }
        public ushort AttributeLength { get; protected set; }
        public byte[]? Value { get; protected set; }

        public IReadOnlyList<byte> Bytes
        {
            get
            {
                _byteArray = ToByteArray();
                return _byteArray.ToList().AsReadOnly();
            }
            private set => _byteArray = [.. value];
        }

        public static MessageAttribute Parse(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 4)
                throw new ArgumentOutOfRangeException(nameof(bytes), "Message attributes must be at least 4 bytes long");

            var bytesSpan = (ReadOnlySpan<byte>)bytes;

            var aType = BitConverter.ToUInt16([bytes[1], bytes[0]]);
            var aLen = BitConverter.ToUInt16([bytes[3], bytes[2]]);
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
                Value = aVal,
                Bytes = bytes
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
                        case AttributeType.ChangeRequest:
                            yield return ChangeRequestAttribute.FromGenericAttribute(nextAttribute);
                            break;

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

        public static byte[] ToByteArray(MessageAttribute attribute)
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
            Array.Copy(BitConverter.GetBytes(MessageUtility.SwapBytes((ushort)attribute.Type)), 0, ret, 0, 2);
            Array.Copy(BitConverter.GetBytes(MessageUtility.SwapBytes((ushort)attribute.Value.Length)), 0, ret, 2, 2);
            Array.Copy(attribute.Value.ToArray(), 0, ret, 4, attribute.Value.Length);
            return ret;
        }

        public void PrintDebug()
        {
            Console.WriteLine($"| Type = 0x{BitConverter.GetBytes((ushort)Type).Reverse().Select(b => $"{b:x2}").Aggregate((c, n) => c + n)} {(Enum.GetName(typeof(AttributeType), Type) ?? "Unknown").PadRight(16, ' ')}| MsgLen = {AttributeLength.ToString().PadRight(21, ' ')}|");
            Console.WriteLine($"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
            for (var i = 0; i < AttributeLength / 4 && Value != null; i++)
                Console.WriteLine($"|                          {Value.Skip(i * 4).Take(4).Select(b => $"{b:x2} ").Reverse().Aggregate((c, n) => c + n).PadRight(37, ' ')}|");
            Console.WriteLine($"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
        }

        public byte[] ToByteArray() => ToByteArray(this);
    }
}
