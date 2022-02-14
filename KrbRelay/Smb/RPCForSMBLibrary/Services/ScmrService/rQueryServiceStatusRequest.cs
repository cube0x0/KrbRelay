using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rQueryServiceStatus   Request (opnum 06)
/// </summary>
public class rQueryServiceStatusRequest : IRPCRequest
{
    public LPSC_RPC_HANDLE hService;

    public rQueryServiceStatusRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        //writer.WriteEmbeddedStructureFullPointer(null);
        writer.WriteStructure(hService);
        return writer.GetBytes();
    }
}