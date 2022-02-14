using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rControlService   Request (opnum 01)
/// </summary>
public class rControlServiceRequest : IRPCRequest
{
    public LPSC_RPC_HANDLE hService;
    public uint dwControl;

    public rControlServiceRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(hService);
        writer.WriteUInt32(dwControl);
        return writer.GetBytes();
    }
}