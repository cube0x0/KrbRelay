using SMBLibrary.RPC;

/// <summary>
/// samrCloseHandle Response (opnum 01)
/// </summary>
public class samrCloseHandleResponse
{
    //public SamprHandle SamrHandle;

    public samrCloseHandleResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        //SamrHandle = new SamprHandle();
        //parser.ReadStructure(SamrHandle);
    }
}