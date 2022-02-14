namespace SMBLibrary.Server
{
    public enum SMBDialect
    {
        NotSet,
        NTLM012, // NT LM 0.12
        SMB202,  // SMB 2.0.2
        SMB210,  // SMB 2.1
        SMB300,  // SMB 3.0
    }
}