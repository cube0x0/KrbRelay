using SMBLibrary.RPC;

/// <summary>
/// schRpcRun Response (opnum 01)
/// </summary>
public class schRpcRunResponse
{
    //public SamprHandle SamrHandle;

    public schRpcRunResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        //SamrHandle = new SamprHandle();
        //parser.ReadStructure(SamrHandle);
    }
}