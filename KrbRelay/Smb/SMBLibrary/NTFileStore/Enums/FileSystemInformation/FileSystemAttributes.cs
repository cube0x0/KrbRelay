using System;

namespace SMBLibrary
{
    [Flags]
    public enum FileSystemAttributes : uint
    {
        CaseSensitiveSearch = 0x0001,            // FILE_CASE_SENSITIVE_SEARCH
        CasePreservedNamed = 0x0002,             // FILE_CASE_PRESERVED_NAMES
        UnicodeOnDisk = 0x0004,                  // FILE_UNICODE_ON_DISK
        PersistentACLs = 0x0008,                 // FILE_PERSISTENT_ACLS
        FileCompression = 0x0010,                // FILE_FILE_COMPRESSION
        VolumeQuotas = 0x0020,                   // FILE_VOLUME_QUOTAS
        SupportsSparseFiles = 0x0040,            // FILE_SUPPORTS_SPARSE_FILES
        SupportsReparsePoints = 0x0080,          // FILE_SUPPORTS_REPARSE_POINTS
        SupportsRemoteStorage = 0x0100,          // FILE_SUPPORTS_REMOTE_STORAGE
        VolumeIsCompressed = 0x8000,             // FILE_VOLUME_IS_COMPRESSED
        SupportsObjectIDs = 0x00010000,          // FILE_SUPPORTS_OBJECT_IDS
        SupportsEncryption = 0x00020000,         // FILE_SUPPORTS_ENCRYPTION
        NamedStreams = 0x00040000,               // FILE_NAMED_STREAMS
        ReadOnlyVolume = 0x00080000,             // FILE_READ_ONLY_VOLUME
        SequentialWriteOnce = 0x00100000,        // FILE_SEQUENTIAL_WRITE_ONCE
        SupportsTransactions = 0x00200000,       // FILE_SUPPORTS_TRANSACTIONS
        SupportsHardLinks = 0x00400000,          // FILE_SUPPORTS_HARD_LINKS
        SupportsExtendedAttributes = 0x00800000, // FILE_SUPPORTS_EXTENDED_ATTRIBUTES
        SupportsOpenByFileID = 0x01000000,       // FILE_SUPPORTS_OPEN_BY_FILE_ID
        SupportsUSNJournal = 0x02000000,         // FILE_SUPPORTS_USN_JOURNAL
    }
}