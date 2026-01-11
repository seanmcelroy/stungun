using System;
using System.Collections.Generic;
using System.Linq;

namespace stungun.common.core
{
    /// <summary>
    /// Result of parsing attributes, including any unknown comprehension-required types encountered.
    /// </summary>
    public class AttributeParseResult
    {
        public List<MessageAttribute> Attributes { get; } = new List<MessageAttribute>();
        public List<ushort> UnknownComprehensionRequiredTypes { get; } = new List<ushort>();
        public bool HasUnknownComprehensionRequired => UnknownComprehensionRequiredTypes.Count > 0;
    }

    public class MessageAttribute
    {
        private byte[]? _byteArray;

        public AttributeType Type { get; protected set; }
        public ushort AttributeLength { get; protected set; }
        public byte[]? Value { get; protected set; }

        /// <summary>
        /// For unknown attributes, stores the raw type value.
        /// </summary>
        public ushort RawType { get; protected set; }

        public IReadOnlyList<byte> Bytes
        {
            get
            {
                _byteArray = ToByteArray();
                return _byteArray.ToList().AsReadOnly();
            }
            private set => _byteArray = [.. value];
        }

        public static MessageAttribute Parse(byte[] bytes) => Parse(bytes, out _);

        /// <summary>
        /// Parses a single attribute from the byte array.
        /// </summary>
        /// <param name="bytes">The raw bytes to parse.</param>
        /// <param name="unknownComprehensionRequired">
        /// If the attribute is an unknown comprehension-required type, this will be set to the raw type value.
        /// Otherwise, it will be null.
        /// </param>
        /// <returns>The parsed attribute, or an Unknown attribute if not recognized.</returns>
        public static MessageAttribute Parse(byte[] bytes, out ushort? unknownComprehensionRequired)
        {
            unknownComprehensionRequired = null;

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
                // Comprehension-optional attributes have type >= 0x8000
                if (aType >= 0x8000 && aType <= 0xFFFF)
                {
                    Console.Error.WriteLine($"Skipping unknown comprehension-optional attribute: 0x{aType:x4}");
                    return new MessageAttribute
                    {
                        Type = AttributeType.Unknown,
                        RawType = aType,
                        AttributeLength = aLen,
                        Value = aVal
                    };
                }

                // Comprehension-required attributes have type < 0x8000
                // Instead of throwing, we return an Unknown attribute and track the type
                Console.Error.WriteLine($"Unknown comprehension-required attribute: 0x{aType:x4}");
                unknownComprehensionRequired = aType;
                return new MessageAttribute
                {
                    Type = AttributeType.Unknown,
                    RawType = aType,
                    AttributeLength = aLen,
                    Value = aVal
                };
            }

            var ret = new MessageAttribute
            {
                Type = (AttributeType)aType,
                RawType = aType,
                AttributeLength = aLen,
                Value = aVal,
                Bytes = bytes
            };

            return ret;
        }

        /// <summary>
        /// Parses a list of attributes from the byte array.
        /// This overload is for backward compatibility and ignores unknown comprehension-required types.
        /// </summary>
        public static IEnumerable<MessageAttribute> ParseList(byte[] bytes, byte[] transactionId)
        {
            var result = ParseListWithResult(bytes, transactionId);
            return result.Attributes;
        }

        /// <summary>
        /// Parses a list of attributes from the byte array, also returning any unknown
        /// comprehension-required attribute types encountered.
        /// </summary>
        public static AttributeParseResult ParseListWithResult(byte[] bytes, byte[] transactionId)
        {
            var result = new AttributeParseResult();

            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 4)
            {
                // No attributes to parse
                return result;
            }

            var attrOffset = 0;
            do
            {
                // Account for padding to 4-byte boundary
                var paddedOffset = attrOffset;
                if (paddedOffset % 4 != 0)
                    paddedOffset += 4 - (paddedOffset % 4);

                if (paddedOffset >= bytes.Length)
                    break;

                var nextAttribute = Parse(bytes.Skip(paddedOffset).ToArray(), out var unknownType);

                if (unknownType.HasValue)
                {
                    result.UnknownComprehensionRequiredTypes.Add(unknownType.Value);
                }

                if (nextAttribute != null && nextAttribute.Type != AttributeType.Unknown)
                {
                    var typedAttribute = nextAttribute.Type switch
                    {
                        AttributeType.ChangeRequest =>
                            ChangeRequestAttribute.FromGenericAttribute(nextAttribute),

                        AttributeType.MappedAddress =>
                            MappedAddressAttribute.FromGenericAttribute(nextAttribute),

                        AttributeType.XorMappedAddress or AttributeType.XorMappedAddress2 =>
                            XorMappedAddressAttribute.FromGenericAttribute(nextAttribute, transactionId),

                        AttributeType.ReservedResponseAddress or
                        AttributeType.ReservedSourceAddress or
                        AttributeType.ReservedChangedAddress or
                        AttributeType.AlternateServer or
                        AttributeType.ResponseOrigin or
                        AttributeType.OtherAddress =>
                            AddressAttribute.FromGenericAttribute(nextAttribute),

                        AttributeType.ErrorCode =>
                            ErrorCodeAttribute.FromGenericAttribute(nextAttribute),

                        AttributeType.UnknownAttributes =>
                            UnknownAttributesAttribute.FromGenericAttribute(nextAttribute),

                        _ => nextAttribute
                    };

                    result.Attributes.Add(typedAttribute);
                }

                attrOffset = paddedOffset + 4 + (nextAttribute?.AttributeLength ?? 0);
            } while (attrOffset < bytes.Length);

            return result;
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
