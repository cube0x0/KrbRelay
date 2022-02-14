namespace SMBLibrary
{
    public enum FileStatus : uint
    {
        FILE_SUPERSEDED = 0x00000000,
        FILE_OPENED = 0x00000001,
        FILE_CREATED = 0x00000002,
        FILE_OVERWRITTEN = 0x00000003,
        FILE_EXISTS = 0x00000004,
        FILE_DOES_NOT_EXIST = 0x00000005,
    }
}