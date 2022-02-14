namespace SMBLibrary.NetBios
{
    public enum NameServiceOperation : byte
    {
        QueryRequest = 0x00,
        RegistrationRequest = 0x05,
        ReleaseRequest = 0x06,
        WackRequest = 0x07,
        RefreshRequest = 0x08,
        QueryResponse = 0x10,
        RegistrationResponse = 0x15,
        ReleaseResponse = 0x16,
        WackResponse = 0x17,
        RefreshResponse = 0x18,
    }
}