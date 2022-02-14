using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum OptionalSupportFlags : ushort
    {
        /// <summary>
        /// The server supports the use of SMB_FILE_ATTRIBUTES exclusive search attributes in client requests.
        /// </summary>
        SMB_SUPPORT_SEARCH_BITS = 0x0001,

        SMB_SHARE_IS_IN_DFS = 0x0002,

        SMB_CSC_CACHE_MANUAL_REINT = 0x0000, // SMB_CSC_MASK = 0
        SMB_CSC_CACHE_AUTO_REINT = 0x0004,   // SMB_CSC_MASK = 1
        SMB_CSC_CACHE_VDO = 0x0008,          // SMB_CSC_MASK = 2
        SMB_CSC_NO_CACHING = 0x000C,         // SMB_CSC_MASK = 3

        SMB_UNIQUE_FILE_NAME = 0x0010,
        SMB_EXTENDED_SIGNATURES = 0x0020,
    }
}