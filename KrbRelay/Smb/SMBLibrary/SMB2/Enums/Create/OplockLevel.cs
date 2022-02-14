using System;

namespace SMBLibrary.SMB2
{
    [Flags]
    public enum OplockLevel : byte
    {
        None = 0x00,      // SMB2_OPLOCK_LEVEL_NONE
        Level2 = 0x01,    // SMB2_OPLOCK_LEVEL_II
        Exclusive = 0x08, // SMB2_OPLOCK_LEVEL_EXCLUSIVE
        Batch = 0x09,     // SMB2_OPLOCK_LEVEL_BATCH
        Lease = 0xFF,     // SMB2_OPLOCK_LEVEL_LEASE
    }
}