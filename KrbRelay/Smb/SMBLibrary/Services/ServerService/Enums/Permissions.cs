using System;

namespace SMBLibrary.Services
{
    [Flags]
    public enum Permissions : uint
    {
        PERM_FILE_READ = 0x00000001,
        PERM_FILE_WRITE = 0x00000002,
        PERM_FILE_CREATE = 0x00000004,
        ACCESS_EXEC = 0x00000008,
        ACCESS_DELETE = 0x00000010,
        ACCESS_ATRIB = 0x00000020,
        ACCESS_PERM = 0x00000040,
    }
}