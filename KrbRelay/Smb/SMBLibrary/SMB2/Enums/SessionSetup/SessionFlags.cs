using System;

namespace SMBLibrary.SMB2
{
    [Flags]
    public enum SessionFlags : ushort
    {
        IsGuest = 0x01,     // SMB2_SESSION_FLAG_IS_GUEST
        IsNull = 0x02,      // SMB2_SESSION_FLAG_IS_NULL
        EncryptData = 0x04, // SMB2_SESSION_FLAG_ENCRYPT_DATA (SMB 3.x)
    }
}