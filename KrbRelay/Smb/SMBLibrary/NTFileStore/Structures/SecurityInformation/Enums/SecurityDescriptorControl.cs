using System;

namespace SMBLibrary
{
    /// <summary>
    /// SECURITY_DESCRIPTOR_CONTROL
    /// </summary>
    [Flags]
    public enum SecurityDescriptorControl : ushort
    {
        OwnerDefaulted = 0x0001,       // SE_OWNER_DEFAULTED
        GroupDefaulted = 0x0002,       // SE_GROUP_DEFAULTED
        DaclPresent = 0x0004,          // SE_DACL_PRESENT
        DaclDefaulted = 0x0008,        // SE_DACL_DEFAULTED
        SaclPresent = 0x0010,          // SE_SACL_PRESENT
        SaclDefaulted = 0x0020,        // SE_SACL_DEFAULTED
        DaclUntrusted = 0x0040,        // SE_DACL_UNTRUSTED
        ServerSecurity = 0x0080,       // SE_SERVER_SECURITY
        DaclAutoInheritedReq = 0x0100, // SE_DACL_AUTO_INHERIT_REQ
        SaclAutoInheritedReq = 0x0200, // SE_SACL_AUTO_INHERIT_REQ
        DaclAutoInherited = 0x0400,    // SE_DACL_AUTO_INHERITED
        SaclAutoInherited = 0x0800,    // SE_SACL_AUTO_INHERITED
        DaclProtected = 0x1000,        // SE_DACL_PROTECTED
        SaclProtected = 0x2000,        // SE_SACL_PROTECTED
        RMControlValid = 0x4000,       // SE_RM_CONTROL_VALID
        SelfRelative = 0x8000,         // SE_SELF_RELATIVE
    }
}