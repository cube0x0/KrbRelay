namespace SMBLibrary.SMB1
{
    public enum SecurityFlags : byte
    {
        SMB_SECURITY_CONTEXT_TRACKING = 0x01,
        SMB_SECURITY_EFFECTIVE_ONLY = 0x02,
    }
}