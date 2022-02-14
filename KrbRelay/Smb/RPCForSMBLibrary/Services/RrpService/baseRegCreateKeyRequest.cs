using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// baseRegCreateKey   Request (opnum 06)
/// </summary>
public class baseRegCreateKeyRequest : IRPCRequest
{
    public RPC_HKEY hKey;
    public RPC_UNICODE_STRING lpSubKey;
    public RPC_UNICODE_STRING lpClass;
    public uint dwOptions;
    public REGSAM samDesired;
    public RPC_SECURITY_ATTRIBUTES lpSecurityAttributes;
    public LPDWORD lpdwDisposition;

    public baseRegCreateKeyRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(hKey);
        writer.WriteStructure(lpSubKey);
        writer.WriteStructure(lpClass);

        writer.WriteUInt32((uint)dwOptions);
        writer.WriteUInt32((uint)samDesired);

        writer.WriteStructure(lpSecurityAttributes);

        writer.WriteEmbeddedStructureFullPointer(lpdwDisposition);
        writer.WriteUInt32(0x00000002);
        return writer.GetBytes();
    }
}