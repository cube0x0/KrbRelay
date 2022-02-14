using SMBLibrary.RPC;

/// <summary>
/// schRpcDelete Response (opnum 01)
/// </summary>
public class schRpcDeleteResponse
{
    //public SamprHandle SamrHandle;

    public schRpcDeleteResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        //SamrHandle = new SamprHandle();
        //parser.ReadStructure(SamrHandle);
    }
}