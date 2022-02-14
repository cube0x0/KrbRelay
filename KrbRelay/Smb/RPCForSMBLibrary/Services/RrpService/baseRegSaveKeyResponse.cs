using SMBLibrary.RPC;

/// <summary>
/// BaseRegSaveKey    Response (opnum 20)
/// </summary>
public class baseRegSaveKeyResponse
{
    //public RPC_HKEY phkResult;

    public baseRegSaveKeyResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        //phkResult = new RPC_HKEY();
        //parser.ReadStructure(phkResult);
    }
}