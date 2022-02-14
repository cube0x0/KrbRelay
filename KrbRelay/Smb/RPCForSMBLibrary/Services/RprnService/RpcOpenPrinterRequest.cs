using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// RpcOpenPrinter   Request (opnum 01)
/// </summary>
public class RpcOpenPrinterRequest : IRPCRequest
{
    public string pDatatype;
    public DEVMODE_CONTAINER DevModeContainer;
    public uint AccessRequired;

    public RpcOpenPrinterRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteTopLevelUnicodeStringPointer(null);
        writer.WriteTopLevelUnicodeStringPointer(pDatatype);
        writer.WriteStructure(DevModeContainer);
        writer.WriteUInt32(AccessRequired);
        return writer.GetBytes();
    }
}