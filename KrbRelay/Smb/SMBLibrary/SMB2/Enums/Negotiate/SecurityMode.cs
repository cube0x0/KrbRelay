using System;

namespace SMBLibrary.SMB2
{
    [Flags]
    public enum SecurityMode : ushort
    {
        SigningEnabled = 0x0001,  // SMB2_NEGOTIATE_SIGNING_ENABLED
        SigningRequired = 0x0002, // SMB2_NEGOTIATE_SIGNING_REQUIRED
    }
}