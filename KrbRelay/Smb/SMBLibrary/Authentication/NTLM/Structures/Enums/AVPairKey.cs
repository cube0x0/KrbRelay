namespace SMBLibrary.Authentication.NTLM
{
    public enum AVPairKey : ushort
    {
        EOL = 0x0000,
        NbComputerName = 0x0001, // Unicode
        NbDomainName = 0x0002, // Unicode
        DnsComputerName = 0x0003, // Unicode
        DnsDomainName = 0x0004, // Unicode
        DnsTreeName = 0x0005, // Unicode
        Flags = 0x0006, // UInt32
        Timestamp = 0x0006, // Filetime
        SingleHost = 0x0008, // platform-specific BLOB
        TargetName = 0x0009, // Unicode
        ChannelBindings = 0x000A, // MD5 Hash
    }
}