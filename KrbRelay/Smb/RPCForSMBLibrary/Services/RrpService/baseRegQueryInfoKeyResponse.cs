using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// baseRegQueryInfoKey   Response (opnum 16)
/// </summary>
public class baseRegQueryInfoKeyResponse
{
    public RPC_UNICODE_STRING lpClassOut;
    public uint lpcSubKeys;
    public uint lpcbMaxSubKeyLen;
    public uint lpcbMaxClassLen;
    public uint lpcValues;
    public uint lpcbMaxValueNameLen;
    public uint lpcbMaxValueLen;
    public uint lpcbSecurityDescriptor;
    //public PFILETIME lpftLastWriteTime;

    public baseRegQueryInfoKeyResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        lpClassOut = new RPC_UNICODE_STRING();
        parser.ReadStructure(lpClassOut);
        lpcSubKeys = parser.ReadUInt32();
        lpcbMaxSubKeyLen = parser.ReadUInt32();
        lpcbMaxClassLen = parser.ReadUInt32();
        lpcValues = parser.ReadUInt32();
        lpcbMaxValueNameLen = parser.ReadUInt32();
        lpcbMaxValueLen = parser.ReadUInt32();
        lpcbSecurityDescriptor = parser.ReadUInt32();
    }
}