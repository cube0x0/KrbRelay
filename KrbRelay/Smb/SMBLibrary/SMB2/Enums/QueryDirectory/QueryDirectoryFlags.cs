using System;

namespace SMBLibrary.SMB2
{
    [Flags]
    public enum QueryDirectoryFlags : byte
    {
        SMB2_RESTART_SCANS = 0x01,
        SMB2_RETURN_SINGLE_ENTRY = 0x02,
        SMB2_INDEX_SPECIFIED = 0x04,
        SMB2_REOPEN = 0x10,
    }
}