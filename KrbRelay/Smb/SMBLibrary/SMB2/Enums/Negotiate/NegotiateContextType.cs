namespace SMBLibrary.SMB2
{
    public enum NegotiateContextType : ushort
    {
        SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x0001,
        SMB2_ENCRYPTION_CAPABILITIES = 0x0002,
    }
}