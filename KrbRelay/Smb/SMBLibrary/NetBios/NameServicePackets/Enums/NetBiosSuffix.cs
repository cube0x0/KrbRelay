namespace SMBLibrary.NetBios
{
    /// <summary>
    /// 16th character suffix for netbios name.
    /// see http://support.microsoft.com/kb/163409/en-us
    /// </summary>
    public enum NetBiosSuffix : byte
    {
        WorkstationService = 0x00,
        MessengerService = 0x03,
        DomainMasterBrowser = 0x1B,
        MasterBrowser = 0x1D,
        BrowserServiceElections = 0x1E,
        FileServiceService = 0x20,
    }
}