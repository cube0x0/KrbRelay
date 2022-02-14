using System;

namespace SMBLibrary
{
    [Flags]
    public enum ExtendedAttributeFlags : byte
    {
        FILE_NEED_EA = 0x80,
    }
}