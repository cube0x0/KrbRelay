using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum OpenFlags : ushort
    {
        /// <summary>
        /// If this bit is set, the client requests that the file attribute data in the response be populated.
        /// All fields after the FID in the response are also populated. If this bit is not set,
        /// all fields after the FID in the response are zero.
        /// </summary>
        REQ_ATTRIB = 0x0001,

        /// <summary>
        /// Client requests an exclusive OpLock on the file.
        /// </summary>
        REQ_OPLOCK = 0x0002,

        /// <summary>
        /// Client requests a Batch OpLock on the file.
        /// </summary>
        REQ_OPLOCK_BATCH = 0x0004,

        /// <summary>
        /// SMB 1.0 Addition.
        /// If set, the client is requesting the extended format of the response.
        /// </summary>
        SMB_OPEN_EXTENDED_RESPONSE = 0x0010,
    }
}