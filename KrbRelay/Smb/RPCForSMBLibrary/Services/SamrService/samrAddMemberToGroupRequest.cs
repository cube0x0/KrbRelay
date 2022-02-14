using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// samrAddMemberToGroup  Request (opnum 22)
/// </summary>
public class samrAddMemberToGroupRequest : IRPCRequest
{
    public SamprHandle GroupHandle;
    public uint MemberId;
    public uint Attributes;

    public samrAddMemberToGroupRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(GroupHandle);
        writer.WriteUInt32(MemberId);
        writer.WriteUInt32(Attributes);
        return writer.GetBytes();
    }
}