using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum LockType : byte
    {
        READ_WRITE_LOCK = 0x00,
        SHARED_LOCK = 0x01,
        OPLOCK_RELEASE = 0x02,
        CHANGE_LOCKTYPE = 0x04,

        /// <summary>
        /// Request to cancel all outstanding lock requests for the specified FID and PID.
        /// </summary>
        CANCEL_LOCK = 0x08,

        /// <summary>
        /// Indicates that the LOCKING_ANDX_RANGE format is the 64-bit file offset version.
        /// If this flag is not set, then the LOCKING_ANDX_RANGE format is the 32-bit file offset version
        /// </summary>
        LARGE_FILES = 0x10,
    }
}