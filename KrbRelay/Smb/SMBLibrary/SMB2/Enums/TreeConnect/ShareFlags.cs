using System;

namespace SMBLibrary.SMB2
{
    [Flags]
    public enum ShareFlags : uint
    {
        ManualCaching = 0x00000000,            // SMB2_SHAREFLAG_MANUAL_CACHING
        AutoCaching = 0x00000010,              // SMB2_SHAREFLAG_AUTO_CACHING
        VdoCaching = 0x00000020,               // SMB2_SHAREFLAG_VDO_CACHING
        NoCaching = 0x00000030,                // SMB2_SHAREFLAG_NO_CACHING
        Dfs = 0x00000001,                      // SMB2_SHAREFLAG_DFS
        DfsRoot = 0x00000002,                  // SMB2_SHAREFLAG_DFS_ROOT
        RestrictExclusiveOpens = 0x00000100,   // SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS
        ForceSharedDelete = 0x00000200,        // SMB2_SHAREFLAG_FORCE_SHARED_DELETE
        AllowNamespaceCaching = 0x00000400,    // SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING
        AccessBasedDirectoryEnum = 0x00000800, // SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM
        ForceLevel2Oplock = 0x00001000,        // SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK
        EnableHashV1 = 0x00002000,             // SMB2_SHAREFLAG_ENABLE_HASH_V1 (SMB 2.1)
        EnableHashV2 = 0x00004000,             // SMB2_SHAREFLAG_ENABLE_HASH_V2 (SMB 3.x)
        EncryptData = 0x00008000,              // SMB2_SHAREFLAG_ENCRYPT_DATA (SMB 3.x)
    }
}