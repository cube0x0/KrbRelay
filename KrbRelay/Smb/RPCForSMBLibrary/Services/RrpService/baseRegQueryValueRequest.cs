using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// baseRegQueryValue   Request (opnum 17)
/// </summary>
public class baseRegQueryValueRequest : IRPCRequest
{
    public RPC_HKEY hKey;
    public RPC_UNICODE_STRING lpValueName;
    public LPDWORD lpType;
    public BYTE lpData;
    public LPDWORD lpcbData;
    public LPDWORD lpcbLen;
    public uint dataLen;

    public baseRegQueryValueRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(hKey);
        writer.WriteStructure(lpValueName);
        writer.WriteEmbeddedStructureFullPointer(lpType);
        writer.WriteUInt32(0);
        writer.WriteEmbeddedStructureFullPointer(lpData);
        writer.WriteUInt32(dataLen);
        writer.WriteUInt32(0);
        writer.WriteUInt32(dataLen);
        writer.WriteBytes(new byte[dataLen]);
        writer.WriteEmbeddedStructureFullPointer(lpcbData);
        writer.WriteUInt32(dataLen);
        writer.WriteEmbeddedStructureFullPointer(lpcbLen);
        writer.WriteUInt32(dataLen);
        return writer.GetBytes();
    }
}