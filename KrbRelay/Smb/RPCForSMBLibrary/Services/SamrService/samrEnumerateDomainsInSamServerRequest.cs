using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// samrEnumerateDomainsInSamServer  Request (opnum 06)
/// </summary>
public class samrEnumerateDomainsInSamServerRequest : IRPCRequest
{
    public SamprHandle ServerHandle;
    public uint EnumerationContext;
    public uint PreferedMaximumLength;

    public samrEnumerateDomainsInSamServerRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(ServerHandle);
        writer.WriteUInt32(EnumerationContext);
        writer.WriteUInt32(PreferedMaximumLength);
        return writer.GetBytes();
    }
}