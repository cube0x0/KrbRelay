using System;

namespace SMBLibrary.SMB2
{
    [Flags]
    public enum Capabilities : uint
    {
        DFS = 0x00000001,               // SMB2_GLOBAL_CAP_DFS
        Leasing = 0x00000002,           // SMB2_GLOBAL_CAP_LEASING
        LargeMTU = 0x0000004,           // SMB2_GLOBAL_CAP_LARGE_MTU
        MultiChannel = 0x0000008,       // SMB2_GLOBAL_CAP_MULTI_CHANNEL
        PersistentHandles = 0x00000010, // SMB2_GLOBAL_CAP_PERSISTENT_HANDLES
        DirectoryLeasing = 0x00000020,  // SMB2_GLOBAL_CAP_DIRECTORY_LEASING
        Encryption = 0x00000040,        // SMB2_GLOBAL_CAP_ENCRYPTION (SMB 3.x)
    }
}