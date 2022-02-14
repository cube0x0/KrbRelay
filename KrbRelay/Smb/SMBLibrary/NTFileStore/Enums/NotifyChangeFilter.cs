using System;

namespace SMBLibrary
{
    [Flags]
    public enum NotifyChangeFilter : uint
    {
        FileName = 0x0000001,     // FILE_NOTIFY_CHANGE_FILE_NAME
        DirName = 0x0000002,      // FILE_NOTIFY_CHANGE_DIR_NAME
        Attributes = 0x0000004,   // FILE_NOTIFY_CHANGE_ATTRIBUTES
        Size = 0x0000008,         // FILE_NOTIFY_CHANGE_SIZE
        LastWrite = 0x000000010,  // FILE_NOTIFY_CHANGE_LAST_WRITE
        LastAccess = 0x00000020,  // FILE_NOTIFY_CHANGE_LAST_ACCESS
        Creation = 0x00000040,    // FILE_NOTIFY_CHANGE_CREATION
        EA = 0x00000080,          // FILE_NOTIFY_CHANGE_EA
        Security = 0x00000100,    // FILE_NOTIFY_CHANGE_SECURITY
        StreamName = 0x00000200,  // FILE_NOTIFY_CHANGE_STREAM_NAME
        StreamSize = 0x00000400,  // FILE_NOTIFY_CHANGE_STREAM_SIZE
        StreamWrite = 0x00000800, // FILE_NOTIFY_CHANGE_STREAM_WRITE
    }
}