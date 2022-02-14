using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// baseRegOpenKey   Request (opnum 15)
/// </summary>
public class baseRegOpenKeyRequest : IRPCRequest
{
    public RPC_HKEY hKey;
    public RPC_UNICODE_STRING lpSubKey;
    public uint dwOptions;
    public REGSAM samDesired;

    public baseRegOpenKeyRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(hKey);
        writer.WriteStructure(lpSubKey);
        writer.WriteUInt32((uint)dwOptions);
        writer.WriteUInt32((uint)samDesired);
        return writer.GetBytes();
    }
}