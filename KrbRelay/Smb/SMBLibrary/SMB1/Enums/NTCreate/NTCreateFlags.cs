using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum NTCreateFlags : uint
    {
        /// <summary>
        /// If set, the client requests an exclusive OpLock.
        /// </summary>
        NT_CREATE_REQUEST_OPLOCK = 0x00000002,

        /// <summary>
        /// If set, the client requests an exclusive batch OpLock.
        /// </summary>
        NT_CREATE_REQUEST_OPBATCH = 0x00000004,

        NT_CREATE_OPEN_TARGET_DIR = 0x00000008,
        NT_CREATE_REQUEST_EXTENDED_RESPONSE = 0x00000010, // SMB 1.0 addition
    }
}