using System;

namespace stungun.common.core
{
    public sealed class ChangeRequestAttribute : MessageAttribute
    {
        private UInt32 bitValue;

        public bool ChangeIP
        {
            get => (bitValue & (1 << 2 - 1)) != 0;
            set
            {
                bitValue |= 1 << 2;
                Value = BitConverter.GetBytes(bitValue);
            }
        }

        public bool ChangePort
        {
            get => (bitValue & (1 << 1 - 1)) != 0;
            set
            {
                bitValue |= 1 << 1;
                Value = BitConverter.GetBytes(bitValue);
            }
        }

        public ChangeRequestAttribute()
        {
            Type = AttributeType.ChangeRequest;
            AttributeLength = 4;
            Value = BitConverter.GetBytes(bitValue);
        }

        public static ChangeRequestAttribute FromGenericAttribute(MessageAttribute attr)
        {
            return new ChangeRequestAttribute
            {
                Type = attr.Type,
                AttributeLength = attr.AttributeLength,
                Value = attr.Value,
                bitValue = BitConverter.ToUInt32(attr.Value)
            };
        }

        public override string ToString() => $"ChangeIP={ChangeIP},ChangePort={ChangePort}";
    }
}
