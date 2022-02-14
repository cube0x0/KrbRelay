using SMBLibrary;
using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// samrOpenGroup  Request (opnum 19)
/// </summary>
public class samrOpenGroupRequest : IRPCRequest
{
    public SamprHandle DomainHandle;
    public AccessMask DesiredAccess;
    public uint GroupId;

    public samrOpenGroupRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(DomainHandle);
        writer.WriteUInt32((uint)DesiredAccess);
        writer.WriteUInt32(GroupId);
        return writer.GetBytes();
    }
}