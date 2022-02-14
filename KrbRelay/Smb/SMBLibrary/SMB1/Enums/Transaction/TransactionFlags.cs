using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum TransactionFlags : ushort
    {
        DISCONNECT_TID = 0x0001,
        NO_RESPONSE = 0x0002,
    }
}