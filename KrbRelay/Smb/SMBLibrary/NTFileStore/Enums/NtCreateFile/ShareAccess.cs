using System;

namespace SMBLibrary
{
    /// <summary>
    /// No bits set = Prevents the file from being shared
    /// </summary>
    [Flags]
    public enum ShareAccess : uint
    {
        None = 0x00000000,   // FILE_SHARE_NONE
        Read = 0x00000001,   // FILE_SHARE_READ
        Write = 0x00000002,  // FILE_SHARE_WRITE
        Delete = 0x00000004, // FILE_SHARE_DELETE
    }
}