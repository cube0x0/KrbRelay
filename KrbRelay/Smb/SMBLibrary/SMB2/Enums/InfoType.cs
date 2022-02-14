namespace SMBLibrary.SMB2
{
    public enum InfoType : byte
    {
        File = 0x01,       // SMB2_0_INFO_FILE
        FileSystem = 0x02, // SMB2_0_INFO_FILESYSTEM
        Security = 0x03,   // SMB2_0_INFO_SECURITY
        Quota = 0x04,      // SMB2_0_INFO_QUOTA
    }
}