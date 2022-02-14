using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// samrSetInformationUser2  Request (opnum 37)
/// </summary>
public class samrSetInformationUserRequest2 : IRPCRequest
{
    public SamprHandle UserHandle;
    public uint UserInformationClass;
    public SAMPR_USER_INFO_BUFFER Buffer;

    public samrSetInformationUserRequest2()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(UserHandle);
        writer.WriteUInt16((ushort)UserInformationClass);
        writer.WriteUInt16((ushort)UserInformationClass);
        writer.WriteStructure(Buffer);
        return writer.GetBytes();
    }
}