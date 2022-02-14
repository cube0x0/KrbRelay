using System;

namespace SMBLibrary
{
    [Flags]
    public enum AceFlags : byte
    {
        OBJECT_INHERIT_ACE = 0x01,
        CONTAINER_INHERIT_ACE = 0x02,
        NO_PROPAGATE_INHERIT_ACE = 0x04,
        INHERIT_ONLY_ACE = 0x08,
        INHERITED_ACE = 0x10,
        SUCCESSFUL_ACCESS_ACE_FLAG = 0x40,
        FAILED_ACCESS_ACE_FLAG = 0x80,
    }
}