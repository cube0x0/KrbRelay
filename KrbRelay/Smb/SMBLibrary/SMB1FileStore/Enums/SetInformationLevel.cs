namespace SMBLibrary.SMB1
{
    public enum SetInformationLevel : ushort
    {
        SMB_INFO_STANDARD = 0x0001,             // LANMAN2.0
        SMB_INFO_SET_EAS = 0x0002,              // LANMAN2.0
        SMB_SET_FILE_BASIC_INFO = 0x0101,
        SMB_SET_FILE_DISPOSITION_INFO = 0x0102,
        SMB_SET_FILE_ALLOCATION_INFO = 0x0103,
        SMB_SET_FILE_END_OF_FILE_INFO = 0x0104,
    }
}