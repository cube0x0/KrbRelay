using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rpcEnumPrinterDrivers   Response (opnum 10)
/// </summary>
public class rpcEnumPrinterDriversResponse
{
    public BYTE pDrivers;
    public uint pcbNeeded;
    public uint pcReturned;

    public rpcEnumPrinterDriversResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        parser.BeginStructure();
        pDrivers = new BYTE();
        parser.ReadStructure(pDrivers);
        pcbNeeded = parser.ReadUInt32();
        pcReturned = parser.ReadUInt32();
        parser.EndStructure();
    }
}