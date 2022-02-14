namespace SMBLibrary.SMB2
{
    public enum ShareType : byte
    {
        Disk = 0x01,  // SMB2_SHARE_TYPE_DISK
        Pipe = 0x02,  // SMB2_SHARE_TYPE_PIPE
        Print = 0x03, // SMB2_SHARE_TYPE_PRINT
    }
}