namespace SMBLibrary.Authentication.NTLM
{
    public enum MessageTypeName : uint
    {
        Negotiate = 0x01,
        Challenge = 0x02,
        Authenticate = 0x03,
    }
}