using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// RpcClosePrinter   Request (opnum 29)
/// </summary>
public class RpcClosePrinterRequest : IRPCRequest
{
    public PRINTER_HANDLE pHandle;

    public RpcClosePrinterRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(pHandle);
        return writer.GetBytes();
    }
}