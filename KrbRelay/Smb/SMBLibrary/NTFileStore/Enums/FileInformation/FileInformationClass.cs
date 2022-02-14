namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.4 - File Information Classes
    /// </summary>
    public enum FileInformationClass : byte
    {
        FileDirectoryInformation = 0x01,       // Uses: Query
        FileFullDirectoryInformation = 0x02,   // Uses: Query
        FileBothDirectoryInformation = 0x03,   // Uses: Query
        FileBasicInformation = 0x04,           // Uses: Query, Set
        FileStandardInformation = 0x05,        // Uses: Query
        FileInternalInformation = 0x06,        // Uses: Query
        FileEaInformation = 0x07,              // Uses: Query
        FileAccessInformation = 0x08,          // Uses: Query
        FileNameInformation = 0x09,            // Uses: LOCAL
        FileRenameInformation = 0x0A,          // Uses: Set
        FileLinkInformation = 0x0B,            // Uses: Set
        FileNamesInformation = 0x0C,           // Uses: Query
        FileDispositionInformation = 0x0D,     // Uses: Set
        FilePositionInformation = 0x0E,        // Uses: Query, Set
        FileFullEaInformation = 0x0F,          // Uses: Query, Set
        FileModeInformation = 0x10,            // Uses: Query, Set
        FileAlignmentInformation = 0x11,       // Uses: Query
        FileAllInformation = 0x12,             // Uses: Query
        FileAllocationInformation = 0x13,      // Uses: Set
        FileEndOfFileInformation = 0x14,       // Uses: Set
        FileAlternateNameInformation = 0x15,   // Uses: Query
        FileStreamInformation = 0x16,          // Uses: Query
        FilePipeInformation = 0x17,            // Uses: Query, Set
        FilePipeLocalInformation = 0x18,       // Uses: Query
        FilePipeRemoteInformation = 0x19,      // Uses: Query
        FileCompressionInformation = 0x1C,     // Uses: Query
        FileNetworkOpenInformation = 0x22,     // Uses: Query
        FileAttributeTagInformation = 0x23,    // Uses: Query
        FileIdBothDirectoryInformation = 0x25, // Uses: Query
        FileIdFullDirectoryInformation = 0x26, // Uses: Query
        FileValidDataLengthInformation = 0x27, // Uses: Set
        FileShortNameInformation = 0x28,       // Uses: Set
    }
}