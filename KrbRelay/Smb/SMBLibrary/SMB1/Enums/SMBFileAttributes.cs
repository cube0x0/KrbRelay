using System;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_FILE_ATTRIBUTES
    /// </summary>
    [Flags]
    public enum SMBFileAttributes : ushort
    {
        Normal = 0x0000, // SMB_FILE_ATTRIBUTE_NORMAL
        ReadOnly = 0x0001, // SMB_FILE_ATTRIBUTE_READONLY
        Hidden = 0x0002, // SMB_FILE_ATTRIBUTE_HIDDEN
        System = 0x0004, // SMB_FILE_ATTRIBUTE_SYSTEM
        Volume = 0x0008, // SMB_FILE_ATTRIBUTE_VOLUME
        Directory = 0x0010, // SMB_FILE_ATTRIBUTE_DIRECTORY
        Archive = 0x0020, // SMB_FILE_ATTRIBUTE_ARCHIVE
        SearchReadOnly = 0x0100, // SMB_SEARCH_ATTRIBUTE_READONLY
        SearchHidden = 0x0200, // SMB_SEARCH_ATTRIBUTE_HIDDEN
        SearchSystem = 0x0400, // SMB_SEARCH_ATTRIBUTE_SYSTEM
        SearchDirectory = 0x1000, // SMB_SEARCH_ATTRIBUTE_DIRECTORY
        SearchArchive = 0x2000, // SMB_SEARCH_ATTRIBUTE_ARCHIVE
    }
}