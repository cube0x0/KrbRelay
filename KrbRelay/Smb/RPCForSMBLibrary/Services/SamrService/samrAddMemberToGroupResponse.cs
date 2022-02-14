using SMBLibrary.RPC;

/// <summary>
/// samrAddMemberToGroup Response (opnum 22)
/// </summary>
public class samrAddMemberToGroupResponse
{
    //public uint ErrorCode;

    public samrAddMemberToGroupResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        //parser.ReadUInt32();
    }
}