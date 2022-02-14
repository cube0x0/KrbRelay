using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// baseRegOpenKey   Response (opnum 15)
/// </summary>
public class baseRegOpenKeyResponse
{
    public RPC_HKEY phkResult;

    public baseRegOpenKeyResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        phkResult = new RPC_HKEY();
        parser.ReadStructure(phkResult);
    }
}