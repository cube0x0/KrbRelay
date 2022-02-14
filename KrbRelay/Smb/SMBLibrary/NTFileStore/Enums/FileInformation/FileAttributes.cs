using System;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.6 - FileAttributes
    /// </summary>
    [Flags]
    public enum FileAttributes : uint
    {
        ReadOnly = 0x00000001,          // FILE_ATTRIBUTE_READONLY
        Hidden = 0x00000002,            // FILE_ATTRIBUTE_HIDDEN
        System = 0x00000004,            // FILE_ATTRIBUTE_SYSTEM
        Directory = 0x00000010,         // FILE_ATTRIBUTE_DIRECTORY
        Archive = 0x00000020,           // FILE_ATTRIBUTE_ARCHIVE

        /// <summary>
        /// A file that does not have other attributes set.
        /// This attribute is valid only when used alone.
        /// </summary>
        Normal = 0x00000080,            // FILE_ATTRIBUTE_NORMAL

        Temporary = 0x00000100,         // FILE_ATTRIBUTE_TEMPORARY
        SparseFile = 0x00000200,        // FILE_ATTRIBUTE_SPARSE_FILE
        ReparsePoint = 0x00000400,      // FILE_ATTRIBUTE_REPARSE_POINT
        Compressed = 0x00000800,        // FILE_ATTRIBUTE_COMPRESSED
        Offline = 0x00001000,           // FILE_ATTRIBUTE_OFFLINE
        NotContentIndexed = 0x00002000, // FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
        Encrypted = 0x00004000,         // FILE_ATTRIBUTE_ENCRYPTED
        IntegrityStream = 0x00008000,   // FILE_ATTRIBUTE_INTEGRITY_STREAM
        NoScrubData = 0x00020000,       // FILE_ATTRIBUTE_NO_SCRUB_DATA
    }
}