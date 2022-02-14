using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// samrOpenUser Response (opnum 34)
/// </summary>
public class samrOpenUserResponse
{
    public SamprHandle UserHandle;

    public samrOpenUserResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        UserHandle = new SamprHandle();
        parser.ReadStructure(UserHandle);
    }
}