using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// samrEnumerateDomainsInSamServer  Request (opnum 05)
/// </summary>
public class samrLookupDomainInSamServerRequest : IRPCRequest
{
    public SamprHandle ServerHandle;
    public NDRUnicodeString Name;

    public samrLookupDomainInSamServerRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(ServerHandle);
        writer.WriteStructure(Name);
        return writer.GetBytes();
    }
}