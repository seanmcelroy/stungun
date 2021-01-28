namespace stungun.common.client
{
    public enum NatTypeRfc3489
    {
        Unknown = 0,
        UdpBlocked = 1,
        SymmetricUdpFirewall = 2,
        OpenInternet = 3,
        FullCone = 4,
        SymmetricNat = 5,
        RestrictedCone = 6,
        PortRestrictedCone = 7
    }
}
