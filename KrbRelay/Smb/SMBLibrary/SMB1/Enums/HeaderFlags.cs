using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum HeaderFlags : byte
    {
        LockAndRead = 0x01, // SMB_FLAGS_LOCK_AND_READ_OK
        CaseInsensitive = 0x08, // SMB_FLAGS_CASE_INSENSITIVE
        CanonicalizedPaths = 0x10, // SMB_FLAGS_CANONICALIZED_PATHS
        Oplock = 0x20, // SMB_FLAGS_OPLOCK
        Reply = 0x80, // SMB_FLAGS_REPLY
    }
}