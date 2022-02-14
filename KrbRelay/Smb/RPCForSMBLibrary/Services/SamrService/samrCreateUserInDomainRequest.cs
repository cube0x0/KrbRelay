using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// samrCreateUserInDomain  Request (opnum 12)
/// </summary>
public class samrCreateUserInDomainRequest : IRPCRequest
{
    public SamprHandle DomainHandle;
    public RPC_UNICODE_STRING Name;
    public uint DesiredAccess;

    public samrCreateUserInDomainRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(DomainHandle);
        writer.WriteStructure(new RPC_UNICODE_STRING("cubetestt"));
        //writer.WriteUnicodeString("cubetestt");
        writer.WriteUInt32((uint)DesiredAccess);
        return writer.GetBytes();
    }
}