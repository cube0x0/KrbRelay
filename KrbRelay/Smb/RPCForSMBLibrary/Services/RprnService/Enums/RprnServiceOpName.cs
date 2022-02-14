namespace SMBLibrary.Services
{
    public enum RprnServiceOpName : ushort
    {
        RpcOpenPrinter = 1,
        RpcClosePrinter = 29,
        RpcEnumPrinterDrivers = 10,
        RpcAddPrinterDriverEx = 89,
    }
}