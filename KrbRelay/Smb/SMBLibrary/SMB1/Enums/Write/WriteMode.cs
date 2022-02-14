using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum WriteMode : ushort
    {
        WritethroughMode = 0x0001,
        ReadBytesAvailable = 0x0002,
        RAW_MODE = 0x0004,
        MSG_START = 0x0008,
    }
}