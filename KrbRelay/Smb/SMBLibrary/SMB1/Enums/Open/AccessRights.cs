namespace SMBLibrary.SMB1
{
    public enum AccessRights : ushort
    {
        SMB_DA_ACCESS_READ = 0x00,
        SMB_DA_ACCESS_WRITE = 0x01,
        SMB_DA_ACCESS_READ_WRITE = 0x02,
    }
}