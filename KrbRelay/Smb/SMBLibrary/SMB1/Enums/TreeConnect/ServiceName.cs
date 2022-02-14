namespace SMBLibrary.SMB1
{
    public enum ServiceName
    {
        DiskShare,
        PrinterShare,
        NamedPipe,
        SerialCommunicationsDevice,

        /// <summary>
        /// Valid only for request
        /// </summary>
        AnyType,
    }
}