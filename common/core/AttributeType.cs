using System;

namespace stungun.common.core
{
    public enum AttributeType : ushort
    {
        Unknown = 0x0000,
        MappedAddress = 0x0001,
        ReservedResponseAddress = 0x0002,
        ChangeRequest= 0x0003,
        ReservedSourceAddress = 0x0004,
        ReservedChangedAddress = 0x0005,
        Username = 0x0006,
        ReservedPassword = 0x0007,
        MessageIntegrity = 0x0008,
        ErrorCode = 0x0009,
        UnknownAttributes = 0x000a,
        ReservedReflectedFrom = 0x000b,
        Realm = 0x0014,
        Nonce = 0x0015,
        XorMappedAddress = 0x0020,
        XorMappedAddress2 = 0x8020,
        Software = 0x8022,
        AlternateServer = 0x8023,
        Padding = 0x8026,
        Fingerprint = 0x8028,
        ResponseOrigin = 0x802b,
        OtherAddress = 0x802c,
    }
}
