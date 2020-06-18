namespace stungun.common.core
{
    public class MappedAddressAttribute : AddressAttribute
    {
        public new static MappedAddressAttribute FromGenericAttribute(MessageAttribute attr)
        {
            return new MappedAddressAttribute
            {
                Type = attr.Type,
                AttributeLength = attr.AttributeLength,
                Value = attr.Value
            };
        }

        public override string ToString() => $"{IPAddress}:{Port}";
    }
}