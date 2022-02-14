using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum FindFlags : ushort
    {
        SMB_FIND_CLOSE_AFTER_REQUEST = 0x0001,
        SMB_FIND_CLOSE_AT_EOS = 0x0002,
        SMB_FIND_RETURN_RESUME_KEYS = 0x0004,
        SMB_FIND_CONTINUE_FROM_LAST = 0x0008,
        SMB_FIND_WITH_BACKUP_INTENT = 0x0010,
    }
}