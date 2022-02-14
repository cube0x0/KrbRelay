namespace SMBLibrary.Services
{
    public enum ScmrServiceOpName : ushort
    {
        rCloseServiceHandle = 0,
        rControlService = 1,
        rQueryServiceStatus = 6,
        rChangeServiceConfigW = 11,
        rCreateServiceW = 12,
        rOpenSCManagerW = 15,
        rOpenServiceW = 16,
        rQueryServiceConfigW = 17,
        rStartServiceW = 19,
    }
}