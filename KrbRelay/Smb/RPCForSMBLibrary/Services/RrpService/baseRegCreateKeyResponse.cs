using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// baseRegCreateKey   Response (opnum 06)
/// </summary>
public class baseRegCreateKeyResponse
{
    public RPC_HKEY phkResult;
    public LPDWORD lpdwDisposition;

    public baseRegCreateKeyResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        phkResult = new RPC_HKEY();
        parser.ReadStructure(phkResult);
        parser.ReadEmbeddedStructureFullPointer(ref lpdwDisposition);
        parser.ReadUInt32();
    }
}