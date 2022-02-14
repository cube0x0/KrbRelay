namespace SMBLibrary.Services
{
    /// <summary>
    /// [MS-SRVS] 2.2.2.6
    /// </summary>
    public enum PlatformName : uint
    {
        DOS = 300, // PLATFORM_ID_DOS
        OS2 = 400, // PLATFORM_ID_OS2
        NT = 500, // PLATFORM_ID_NT
        OSF = 600, // PLATFORM_ID_OSF
        VMS = 700, // PLATFORM_ID_VMS
    }
}