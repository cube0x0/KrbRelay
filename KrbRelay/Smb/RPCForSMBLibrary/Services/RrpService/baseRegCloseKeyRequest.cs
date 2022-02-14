using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// baseRegCloseKey   Request (opnum 05
/// </summary>
public class baseRegCloseKeyRequest : IRPCRequest
{
    public RPC_HKEY hKey;

    public baseRegCloseKeyRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(hKey);
        return writer.GetBytes();
    }
}