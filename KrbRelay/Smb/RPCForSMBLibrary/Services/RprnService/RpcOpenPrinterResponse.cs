using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// RpcOpenPrinter   Response (opnum 01)
/// </summary>
public class RpcOpenPrinterResponse
{
    public PRINTER_HANDLE pHandle;

    public RpcOpenPrinterResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);

        parser.BeginStructure();
        pHandle = new PRINTER_HANDLE();
        parser.ReadStructure(pHandle);
        parser.EndStructure();
    }
}