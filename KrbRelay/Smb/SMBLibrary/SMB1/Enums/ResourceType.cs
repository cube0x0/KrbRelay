namespace SMBLibrary.SMB1
{
    public enum ResourceType : ushort
    {
        FileTypeDisk = 0x0000,
        FileTypeByteModePipe = 0x0001,
        FileTypeMessageModePipe = 0x0002,
        FileTypePrinter = 0x0003,

        /// <summary>
        /// OpenAndX Response: Valid.
        /// OpenAndX Extended Response: Invalid (SMB 1.0).
        /// NTCreateAndX Response: Valid.
        /// NTCreateAndX Extended Response: Invalid (SMB 1.0).
        /// Transact2Open2: Was never valid
        /// </summary>
        FileTypeCommDevice = 0x0004,

        /// <summary>
        /// OpenAndX Response: Valid
        /// NTCreateAndX Response: Invalid
        /// Transact2Open2 Response: Valid
        /// TransactCreate Response: Valid
        /// </summary>
        FileTypeUnknown = 0xFFFF,
    }
}