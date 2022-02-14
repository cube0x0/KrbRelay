using System;

namespace SMBLibrary.SMB2
{
    [Flags]
    public enum SMB2PacketHeaderFlags : uint
    {
        ServerToRedir = 0x0000001,     // SMB2_FLAGS_SERVER_TO_REDIR
        AsyncCommand = 0x0000002,      // SMB2_FLAGS_ASYNC_COMMAND
        RelatedOperations = 0x0000004, // SMB2_FLAGS_RELATED_OPERATIONS
        Signed = 0x0000008,            // SMB2_FLAGS_SIGNED
        DfsOperations = 0x10000000,    // SMB2_FLAGS_DFS_OPERATIONS
    }
}