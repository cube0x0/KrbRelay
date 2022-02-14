namespace SMBLibrary.SMB2
{
    public enum CreateAction : uint
    {
        FILE_SUPERSEDED = 0x00000000,
        FILE_OPENED = 0x00000001,
        FILE_CREATED = 0x00000002,
        FILE_OVERWRITTEN = 0x00000003,
    }
}