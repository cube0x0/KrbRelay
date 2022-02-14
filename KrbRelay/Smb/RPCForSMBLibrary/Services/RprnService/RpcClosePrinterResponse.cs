using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// RpcClosePrinter   Response (opnum 029)
/// </summary>
public class RpcClosePrinterResponse
{
    public PRINTER_HANDLE pHandle;

    public RpcClosePrinterResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);

        parser.BeginStructure();
        pHandle = new PRINTER_HANDLE();
        parser.ReadStructure(pHandle);
        parser.EndStructure();
    }
}