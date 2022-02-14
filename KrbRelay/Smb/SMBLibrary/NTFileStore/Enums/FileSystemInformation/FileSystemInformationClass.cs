namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.5 - File System Information Classes
    /// </summary>
    public enum FileSystemInformationClass : byte
    {
        FileFsVolumeInformation = 0x01,     // Uses: Query
        FileFsLabelInformation = 0x02,
        FileFsSizeInformation = 0x03,       // Uses: Query
        FileFsDeviceInformation = 0x04,     // Uses: Query
        FileFsAttributeInformation = 0x05,  // Uses: Query
        FileFsControlInformation = 0x06,    // Uses: Query, Set
        FileFsFullSizeInformation = 0x07,   // Uses: Query
        FileFsObjectIdInformation = 0x08,   // Uses: Query, Set
        FileFsDriverPathInformation = 0x09,
        FileFsVolumeFlagsInformation = 0x0A,
        FileFsSectorSizeInformation = 0x0B, // Uses: Query
    }
}