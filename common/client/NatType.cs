namespace stungun.common.client
{
    public enum NatType
    {
        Unknown = 0,
        UdpBlocked = 1,
        SymmetricUdpFirewall = 2,
        OpenInternet = 3,
        FullCone = 4,
        SymmetricNat = 5,
        Restricted = 6,
        PortRestricted = 7
    }
}
