using SMBLibrary.RPC;

/// <summary>
/// samrSetInformationUser2 Response (opnum 37)
/// </summary>
public class samrSetInformationUserResponse2
{
    //public SamprHandle UserHandle;

    public samrSetInformationUserResponse2(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        //UserHandle = new SamprHandle();
        //parser.ReadStructure(UserHandle);
    }
}