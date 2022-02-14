using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// baseRegOpenKey   Response (opnum 05)
/// </summary>
public class baseRegCloseKeyResponse
{
    public RPC_HKEY hKey;

    public baseRegCloseKeyResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        hKey = new RPC_HKEY();
        parser.ReadStructure(hKey);
    }
}