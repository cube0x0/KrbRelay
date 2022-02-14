using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rOpenServiceW   Response (opnum 16)
/// </summary>
public class rOpenServiceWResponse
{
    public LPSC_RPC_HANDLE lpServiceHandle;

    public rOpenServiceWResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);

        parser.BeginStructure();
        lpServiceHandle = new LPSC_RPC_HANDLE();
        parser.ReadStructure(lpServiceHandle);
        parser.EndStructure();
    }
}