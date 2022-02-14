using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum FileStatusFlags : ushort
    {
        NO_EAS = 0x01,
        NO_SUBSTREAMS = 0x02,
        NO_REPARSETAG = 0x04,
    }
}