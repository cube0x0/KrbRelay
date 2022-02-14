namespace SMBLibrary.SMB1
{
    public enum QueryFSInformationLevel : ushort
    {
        SMB_INFO_ALLOCATION = 0x0001,      // LANMAN2.0
        SMB_INFO_VOLUME = 0x0002,          // LANMAN2.0
        SMB_QUERY_FS_VOLUME_INFO = 0x0102,
        SMB_QUERY_FS_SIZE_INFO = 0x0103,
        SMB_QUERY_FS_DEVICE_INFO = 0x0104,
        SMB_QUERY_FS_ATTRIBUTE_INFO = 0x0105,
    }
}