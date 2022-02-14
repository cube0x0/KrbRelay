using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// samrCreateUserInDomain Response (opnum 12)
/// </summary>
public class samrCreateUserInDomainResponse
{
    public SamprHandle UserHandle;
    public uint RelativeId;

    public samrCreateUserInDomainResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        UserHandle = new SamprHandle();
        parser.ReadStructure(UserHandle);
        RelativeId = parser.ReadUInt32();
    }
}