using System;
using System.Text;

namespace stungun.common.core
{
    /// <summary>
    /// ERROR-CODE attribute as defined in RFC 5389 Section 15.6.
    ///
    /// Wire format:
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |           Reserved, should be 0         |Class|     Number    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |      Reason Phrase (variable)                                ..
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// </summary>
    public class ErrorCodeAttribute : MessageAttribute
    {
        private byte _errorClass;
        private byte _errorNumber;
        private string _reasonPhrase = string.Empty;

        /// <summary>
        /// Error class (hundreds digit of error code). Valid values are 3-6.
        /// </summary>
        public byte ErrorClass
        {
            get => _errorClass;
            set
            {
                if (value < 3 || value > 6)
                    throw new ArgumentOutOfRangeException(nameof(value), "Error class must be between 3 and 6");
                _errorClass = value;
                UpdateValue();
            }
        }

        /// <summary>
        /// Error number (last two digits of error code). Valid values are 0-99.
        /// </summary>
        public byte ErrorNumber
        {
            get => _errorNumber;
            set
            {
                if (value > 99)
                    throw new ArgumentOutOfRangeException(nameof(value), "Error number must be between 0 and 99");
                _errorNumber = value;
                UpdateValue();
            }
        }

        /// <summary>
        /// The full error code (e.g., 401, 420, 500).
        /// </summary>
        public int ErrorCode
        {
            get => (_errorClass * 100) + _errorNumber;
            set
            {
                if (value < 300 || value > 699)
                    throw new ArgumentOutOfRangeException(nameof(value), "Error code must be between 300 and 699");
                _errorClass = (byte)(value / 100);
                _errorNumber = (byte)(value % 100);
                UpdateValue();
            }
        }

        /// <summary>
        /// Human-readable reason phrase. Maximum 127 characters (763 bytes UTF-8).
        /// </summary>
        public string ReasonPhrase
        {
            get => _reasonPhrase;
            set
            {
                if (value != null && value.Length > 127)
                    throw new ArgumentOutOfRangeException(nameof(value), "Reason phrase must be 127 characters or less");
                _reasonPhrase = value ?? string.Empty;
                UpdateValue();
            }
        }

        public ErrorCodeAttribute()
        {
            Type = AttributeType.ErrorCode;
        }

        public ErrorCodeAttribute(int errorCode, string reasonPhrase) : this()
        {
            ErrorCode = errorCode;
            ReasonPhrase = reasonPhrase;
        }

        private void UpdateValue()
        {
            var reasonBytes = Encoding.UTF8.GetBytes(_reasonPhrase);
            var totalLength = 4 + reasonBytes.Length;

            // Store unpadded value - padding is added in ToByteArray
            var value = new byte[totalLength];

            // First 2 bytes are reserved (zeros)
            value[0] = 0;
            value[1] = 0;

            // Third byte: class in lower 3 bits
            value[2] = _errorClass;

            // Fourth byte: number
            value[3] = _errorNumber;

            // Reason phrase
            Array.Copy(reasonBytes, 0, value, 4, reasonBytes.Length);

            Value = value;
            AttributeLength = (ushort)totalLength;
        }

        /// <summary>
        /// Serializes the attribute to bytes, including padding to 4-byte boundary.
        /// </summary>
        public new byte[] ToByteArray()
        {
            if (Value == null || Value.Length == 0)
                throw new InvalidOperationException("Attribute value is not set");

            // Calculate padded length for wire format
            var paddedValueLength = (Value.Length + 3) & ~3;
            var ret = new byte[4 + paddedValueLength];

            // Type (big-endian)
            Array.Copy(BitConverter.GetBytes(MessageUtility.SwapBytes((ushort)Type)), 0, ret, 0, 2);

            // Length (unpadded, big-endian)
            Array.Copy(BitConverter.GetBytes(MessageUtility.SwapBytes(AttributeLength)), 0, ret, 2, 2);

            // Value (with padding)
            Array.Copy(Value, 0, ret, 4, Value.Length);
            // Remaining bytes are already zero (padding)

            return ret;
        }

        public static ErrorCodeAttribute FromGenericAttribute(MessageAttribute attr)
        {
            if (attr == null)
                throw new ArgumentNullException(nameof(attr));
            if (attr.Value == null || attr.Value.Length < 4)
                throw new ArgumentException("ERROR-CODE attribute must be at least 4 bytes", nameof(attr));

            var errorClass = (byte)(attr.Value[2] & 0x07);
            var errorNumber = attr.Value[3];

            string reasonPhrase = string.Empty;
            if (attr.Value.Length > 4)
            {
                // Reason phrase length excludes padding
                var reasonLength = Math.Min(attr.AttributeLength - 4, attr.Value.Length - 4);
                reasonPhrase = Encoding.UTF8.GetString(attr.Value, 4, reasonLength);
            }

            return new ErrorCodeAttribute
            {
                Type = AttributeType.ErrorCode,
                _errorClass = errorClass,
                _errorNumber = errorNumber,
                _reasonPhrase = reasonPhrase,
                Value = attr.Value,
                AttributeLength = attr.AttributeLength
            };
        }

        public override string ToString() => $"ERROR-CODE: {ErrorCode} {ReasonPhrase}";
    }
}
