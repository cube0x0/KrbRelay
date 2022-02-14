using System;

namespace SMBLibrary.SMB2
{
    [Flags]
    public enum CloseFlags : byte
    {
        PostQueryAttributes = 0x0001, // SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
    }
}