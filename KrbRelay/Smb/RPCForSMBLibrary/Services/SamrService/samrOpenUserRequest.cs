using SMBLibrary;
using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// samrOpenUser  Request (opnum 34)
/// </summary>
public class samrOpenUserRequest : IRPCRequest
{
    public SamprHandle DomainHandle;
    public AccessMask DesiredAccess;
    public uint UserId;

    public samrOpenUserRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(DomainHandle);
        writer.WriteUInt32((uint)DesiredAccess);
        writer.WriteUInt32(UserId);
        return writer.GetBytes();
    }
}