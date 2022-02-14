using System;

namespace SMBLibrary.SMB2
{
    [Flags]
    public enum LockFlags : uint
    {
        SharedLock = 0x00000001,      // SMB2_LOCKFLAG_SHARED_LOCK
        ExclusiveLock = 0x00000002,   // SMB2_LOCKFLAG_EXCLUSIVE_LOCK
        Unlock = 0x00000004,          // SMB2_LOCKFLAG_UNLOCK
        FailImmediately = 0x00000008, // SMB2_LOCKFLAG_FAIL_IMMEDIATELY
    }
}