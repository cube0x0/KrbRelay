using SMBLibrary.RPC;

/// <summary>
/// schRpcGetLastRunInfo Response (opnum 01)
/// </summary>
public class schRpcGetLastRunInfoResponse
{
    //public SamprHandle SamrHandle;

    public schRpcGetLastRunInfoResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        //SamrHandle = new SamprHandle();
        //parser.ReadStructure(SamrHandle);
    }
}