using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum SessionSetupAction : ushort
    {
        SetupGuest = 0x01, // SMB_SETUP_GUEST
        UseLanmanKey = 0x02, // SMB_SETUP_USE_LANMAN_KEY
    }
}