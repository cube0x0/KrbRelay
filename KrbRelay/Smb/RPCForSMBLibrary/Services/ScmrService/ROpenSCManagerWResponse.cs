using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// ROpenSCManagerW   Response (opnum 15)
/// </summary>
public class ROpenSCManagerWResponse
{
    public LPSC_RPC_HANDLE lpScHandle;

    public ROpenSCManagerWResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);

        parser.BeginStructure();
        lpScHandle = new LPSC_RPC_HANDLE();
        parser.ReadStructure(lpScHandle);
        parser.EndStructure();
    }
}