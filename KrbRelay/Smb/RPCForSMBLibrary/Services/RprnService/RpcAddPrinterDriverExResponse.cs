using SMBLibrary.RPC;

/// <summary>
/// RpcAddPrinterDriverEx   Response (opnum 89)
/// </summary>
public class RpcAddPrinterDriverExResponse
{
    //public PRINTER_HANDLE pHandle;

    public RpcAddPrinterDriverExResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);

        //parser.BeginStructure();
        //pHandle = new PRINTER_HANDLE();
        //parser.ReadStructure(pHandle);
        //parser.EndStructure();
    }
}