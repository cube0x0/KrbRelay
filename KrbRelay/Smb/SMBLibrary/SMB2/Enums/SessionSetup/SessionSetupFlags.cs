using System;

namespace SMBLibrary.SMB2
{
    [Flags]
    public enum SessionSetupFlags : byte
    {
        Binding = 0x01, // SMB2_SESSION_FLAG_BINDING
    }
}