using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// baseRegQueryValue   Response (opnum 17)
/// </summary>
public class baseRegQueryValueResponse
{
    public LPDWORD lpType;
    public BYTE lpData;
    public LPDWORD lpcbData;
    public LPDWORD lpcbLen;
    public byte[] data;
    public RegType regType;

    public baseRegQueryValueResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        parser.ReadEmbeddedStructureFullPointer(ref lpType);
        regType = (RegType)parser.ReadUInt32();
        parser.ReadEmbeddedStructureFullPointer(ref lpData);
        parser.ReadUInt32();
        parser.ReadUInt32();
        uint count = parser.ReadUInt32();
        data = parser.ReadBytes((int)count);
        parser.ReadEmbeddedStructureFullPointer(ref lpcbData);
        parser.ReadUInt32();
        parser.ReadEmbeddedStructureFullPointer(ref lpcbLen);
        parser.ReadUInt32();
    }
}