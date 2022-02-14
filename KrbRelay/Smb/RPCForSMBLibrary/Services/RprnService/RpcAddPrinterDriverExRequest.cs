using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// RpcAddPrinterDriverEx   Request (opnum 89)
/// </summary>
public class RpcAddPrinterDriverExRequest : IRPCRequest
{
    public string pName;
    public DRIVER_CONTAINER pDriverContainer;
    public uint dwFileCopyFlags;

    public RpcAddPrinterDriverExRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteTopLevelUnicodeStringPointer(null);
        writer.WriteStructure(pDriverContainer);
        writer.WriteUInt32(dwFileCopyFlags);
        return writer.GetBytes();
    }
}