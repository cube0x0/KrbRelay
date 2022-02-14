using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum Open2Flags : ushort
    {
        /// <summary>
        /// Return additional information in the response;
        /// populate the CreationTime, FileDataSize, AccessMode, ResourceType, and NMPipeStatus fields in the response.
        /// </summary>
        REQ_ATTRIB = 0x0001,

        /// <summary>
        /// Exclusive OpLock requested.
        /// </summary>
        REQ_OPLOCK = 0x0002,

        /// <summary>
        /// Batch OpLock requested.
        /// </summary>
        REQ_OPBATCH = 0x0004,

        /// <summary>
        /// Return total length of Extended Attributes (EAs);
        /// populate the ExtendedAttributeLength field in the response.
        /// </summary>
        REQ_EASIZE = 0x0008,
    }
}