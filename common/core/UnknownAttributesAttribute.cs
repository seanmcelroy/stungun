using System;
using System.Collections.Generic;

namespace stungun.common.core
{
    /// <summary>
    /// UNKNOWN-ATTRIBUTES attribute as defined in RFC 5389 Section 15.9.
    ///
    /// Used in error responses (420 Unknown Attribute) to list the
    /// comprehension-required attributes that were not understood.
    ///
    /// Wire format:
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |      Attribute 1 Type           |     Attribute 2 Type        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |      Attribute 3 Type           |     Attribute 4 Type    ...
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// </summary>
    public class UnknownAttributesAttribute : MessageAttribute
    {
        private List<ushort> _unknownTypes = new List<ushort>();

        /// <summary>
        /// List of unknown attribute types that were not understood.
        /// </summary>
        public IReadOnlyList<ushort> UnknownTypes => _unknownTypes.AsReadOnly();

        public UnknownAttributesAttribute()
        {
            Type = AttributeType.UnknownAttributes;
        }

        public UnknownAttributesAttribute(IEnumerable<ushort> unknownTypes) : this()
        {
            if (unknownTypes != null)
            {
                _unknownTypes.AddRange(unknownTypes);
            }
            UpdateValue();
        }

        public void AddUnknownType(ushort attributeType)
        {
            _unknownTypes.Add(attributeType);
            UpdateValue();
        }

        public void AddUnknownTypes(IEnumerable<ushort> attributeTypes)
        {
            _unknownTypes.AddRange(attributeTypes);
            UpdateValue();
        }

        private void UpdateValue()
        {
            // Each attribute type is 2 bytes
            var totalLength = _unknownTypes.Count * 2;

            // Store unpadded value - padding is added in ToByteArray
            var value = new byte[totalLength];

            for (int i = 0; i < _unknownTypes.Count; i++)
            {
                var typeBytes = BitConverter.GetBytes(MessageUtility.SwapBytes(_unknownTypes[i]));
                value[i * 2] = typeBytes[0];
                value[i * 2 + 1] = typeBytes[1];
            }

            Value = value;
            AttributeLength = (ushort)totalLength;
        }

        /// <summary>
        /// Serializes the attribute to bytes, including padding to 4-byte boundary.
        /// </summary>
        public new byte[] ToByteArray()
        {
            Value ??= [];

            // Calculate padded length for wire format
            var paddedValueLength = (Value.Length + 3) & ~3;
            var ret = new byte[4 + paddedValueLength];

            // Type (big-endian)
            Array.Copy(BitConverter.GetBytes(MessageUtility.SwapBytes((ushort)Type)), 0, ret, 0, 2);

            // Length (unpadded, big-endian)
            Array.Copy(BitConverter.GetBytes(MessageUtility.SwapBytes(AttributeLength)), 0, ret, 2, 2);

            // Value (with padding)
            if (Value.Length > 0)
                Array.Copy(Value, 0, ret, 4, Value.Length);
            // Remaining bytes are already zero (padding)

            return ret;
        }

        public static UnknownAttributesAttribute FromGenericAttribute(MessageAttribute attr)
        {
            if (attr == null)
                throw new ArgumentNullException(nameof(attr));

            var result = new UnknownAttributesAttribute
            {
                Value = attr.Value,
                AttributeLength = attr.AttributeLength
            };

            if (attr.Value != null)
            {
                // Read pairs of bytes as attribute types
                var count = attr.AttributeLength / 2;
                for (int i = 0; i < count; i++)
                {
                    var typeValue = (ushort)((attr.Value[i * 2] << 8) | attr.Value[i * 2 + 1]);
                    result._unknownTypes.Add(typeValue);
                }
            }

            return result;
        }

        public override string ToString() =>
            $"UNKNOWN-ATTRIBUTES: [{string.Join(", ", _unknownTypes.ConvertAll(t => $"0x{t:X4}"))}]";
    }
}
