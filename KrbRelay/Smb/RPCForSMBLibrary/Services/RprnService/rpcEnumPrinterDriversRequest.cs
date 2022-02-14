using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rpcEnumPrinterDrivers   Request (opnum 10)
/// </summary>
public class rpcEnumPrinterDriversRequest : IRPCRequest
{
    public string pName;
    public string pEnvironment;
    public uint Level;
    public BYTE pDrivers;
    public uint cbBuf;

    public rpcEnumPrinterDriversRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteTopLevelUnicodeStringPointer(null);
        writer.WriteTopLevelUnicodeStringPointer(pEnvironment);
        writer.WriteUInt32(Level);
        writer.WriteEmbeddedStructureFullPointer(pDrivers);
        writer.WriteUInt32(cbBuf);
        writer.WriteUInt32(cbBuf);
        return writer.GetBytes();
    }
}