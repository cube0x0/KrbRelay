namespace SMBLibrary
{
    /// <summary>
    /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379572(v=vs.85).aspx
    /// https://msdn.microsoft.com/en-us/library/windows/hardware/ff556631(v=vs.85).aspx
    /// </summary>
    public enum ImpersonationLevel : uint
    {
        Anonymous = 0x00000000,      // SECURITY_ANONYMOUS
        Identification = 0x00000001, // SECURITY_IDENTIFICATION
        Impersonation = 0x00000002,  // SECURITY_IMPERSONATION
        Delegation = 0x00000003,     // SECURITY_DELEGATION (This impersonation level is supported starting with Windows 2000)
    }
}