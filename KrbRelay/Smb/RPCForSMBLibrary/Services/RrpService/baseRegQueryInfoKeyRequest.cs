using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// baseRegQueryInfoKey   Request (opnum 16)
/// </summary>
public class baseRegQueryInfoKeyRequest : IRPCRequest
{
    public RPC_HKEY hKey;
    public RPC_UNICODE_STRING2 lpClassIn;

    public baseRegQueryInfoKeyRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(hKey);
        writer.WriteStructure(lpClassIn);
        //writer.WriteTopLevelUnicodeStringPointer("\x00");
        //writer.WriteUInt16(0);
        //writer.WriteUInt16(0);
        //writer.WriteUInt32(0x00020000);
        //writer.WriteUInt32(0);
        //writer.WriteUInt32(0);
        //writer.WriteUInt32(0);
        //writer.WriteUInt32(4);
        //writer.WriteUInt32(5);
        return writer.GetBytes();
    }
}