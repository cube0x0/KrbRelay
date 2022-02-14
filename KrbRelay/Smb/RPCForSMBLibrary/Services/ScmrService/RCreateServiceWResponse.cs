using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// RCreateServiceW   Response (opnum 12)
/// </summary>
public class RCreateServiceWResponse
{
    public string lpdwTagIdl;
    public LPSC_RPC_HANDLE lpScHandle;

    public RCreateServiceWResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);

        parser.BeginStructure();
        parser.ReadTopLevelUnicodeStringPointer();
        lpScHandle = new LPSC_RPC_HANDLE();
        parser.ReadStructure(lpScHandle);
        parser.EndStructure();
    }
}