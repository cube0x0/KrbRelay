using SMBLibrary;
using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// samrOpenDomain  Request (opnum 07)
/// </summary>
public class samrOpenDomainRequest : IRPCRequest
{
    public SamprHandle SamprHandle;
    public AccessMask DesiredAccess;
    public SMBLibrary.SID DomainId;

    public samrOpenDomainRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(SamprHandle);
        writer.WriteUInt32((uint)DesiredAccess);
        writer.WriteStructure(new NDRSID(DomainId));
        return writer.GetBytes();
    }
}