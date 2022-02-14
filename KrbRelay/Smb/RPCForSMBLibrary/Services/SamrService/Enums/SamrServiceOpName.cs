namespace SMBLibrary.Services
{
    public enum SamrServiceOpName : ushort
    {
        SamrConnect = 0,
        SamrCloseHandle = 1,
        SamrLookupDomainInSamServer = 5,
        samrEnumerateDomainsInSamServer = 6,
        SamrOpenDomain = 7,
        SamrCreateUserInDomain = 12,
        samrOpenGroup = 19,
        samrAddMemberToGroup = 22,
        samrOpenUser = 34,
        SamrSetInformationUser = 37,
        SamrSetInformationUser2 = 58,
    }
}