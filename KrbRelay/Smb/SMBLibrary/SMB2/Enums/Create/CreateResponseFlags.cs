using System;

namespace SMBLibrary.SMB2
{
    [Flags]
    public enum CreateResponseFlags : byte
    {
        ReparsePoint = 0x01, // SMB2_CREATE_FLAG_REPARSEPOINT
    }
}