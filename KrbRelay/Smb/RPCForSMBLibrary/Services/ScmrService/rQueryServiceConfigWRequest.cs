using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rQueryServiceConfigW   Request (opnum 17)
/// </summary>
public class rQueryServiceConfigWRequest : IRPCRequest
{
    public LPSC_RPC_HANDLE hService;
    public uint cbBufSize;

    public rQueryServiceConfigWRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(hService);
        writer.WriteUInt32(cbBufSize);
        return writer.GetBytes();
    }
}