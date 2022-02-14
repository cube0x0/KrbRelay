using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// samrOpenGroup Response (opnum 19)
/// </summary>
public class samrOpenGroupResponse
{
    public SamprHandle GroupHandle;

    public samrOpenGroupResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        GroupHandle = new SamprHandle();
        parser.ReadStructure(GroupHandle);
    }
}