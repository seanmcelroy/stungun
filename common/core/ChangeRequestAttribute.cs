using System;

namespace stungun.common.core
{
    /// <summary>
    /// CHANGE-REQUEST attribute as defined in RFC 5780.
    ///
    /// Used to request that the server send the response from a different
    /// IP address and/or port than the one the request was received on.
    ///
    /// Wire format:
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 A B 0|
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    /// A = Change IP flag (0x04)
    /// B = Change Port flag (0x02)
    /// </summary>
    public sealed class ChangeRequestAttribute : MessageAttribute
    {
        private const uint ChangeIpFlag = 0x04;
        private const uint ChangePortFlag = 0x02;

        private uint _flags;

        /// <summary>
        /// When true, requests that the server send the response from a different IP address.
        /// </summary>
        public bool ChangeIP
        {
            get => (_flags & ChangeIpFlag) != 0;
            set
            {
                if (value)
                    _flags |= ChangeIpFlag;
                else
                    _flags &= ~ChangeIpFlag;
                UpdateValue();
            }
        }

        /// <summary>
        /// When true, requests that the server send the response from a different port.
        /// </summary>
        public bool ChangePort
        {
            get => (_flags & ChangePortFlag) != 0;
            set
            {
                if (value)
                    _flags |= ChangePortFlag;
                else
                    _flags &= ~ChangePortFlag;
                UpdateValue();
            }
        }

        public ChangeRequestAttribute()
        {
            Type = AttributeType.ChangeRequest;
            AttributeLength = 4;
            _flags = 0;
            UpdateValue();
        }

        private void UpdateValue()
        {
            // Store as big-endian (network byte order)
            Value = new byte[4];
            Value[0] = 0;
            Value[1] = 0;
            Value[2] = 0;
            Value[3] = (byte)_flags;
        }

        public static ChangeRequestAttribute FromGenericAttribute(MessageAttribute attr)
        {
            if (attr == null)
                throw new ArgumentNullException(nameof(attr));
            if (attr.Value == null || attr.Value.Length < 4)
                throw new ArgumentException("CHANGE-REQUEST attribute must be at least 4 bytes", nameof(attr));

            // Flags are in the last byte (big-endian network order)
            var flags = (uint)attr.Value[3];

            return new ChangeRequestAttribute
            {
                Type = attr.Type,
                AttributeLength = attr.AttributeLength,
                Value = attr.Value,
                _flags = flags
            };
        }

        public override string ToString() => $"CHANGE-REQUEST: ChangeIP={ChangeIP}, ChangePort={ChangePort}";
    }
}
