using SMBLibrary.Client.Helpers;
using SMBLibrary.Services;

namespace SMBLibrary.Client
{
    public class RprnServiceHelper
    {
        public static PRINTER_HANDLE rpcOpenPrinter(RPCCallHelper rpc, out NTStatus status)
        {
            RpcOpenPrinterRequest rpcOpenPrinterRequest = new RpcOpenPrinterRequest();
            rpcOpenPrinterRequest.pDatatype = null;
            rpcOpenPrinterRequest.DevModeContainer = new DEVMODE_CONTAINER();
            rpcOpenPrinterRequest.AccessRequired = 0;

            RpcOpenPrinterResponse rpcOpenPrinterResponse;

            status = rpc.ExecuteCall((ushort)RprnServiceOpName.RpcOpenPrinter, rpcOpenPrinterRequest, out rpcOpenPrinterResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return rpcOpenPrinterResponse.pHandle;
        }

        public static NTStatus rpcEnumPrinterDrivers(RPCCallHelper rpc)
        {
            rpcEnumPrinterDriversRequest rpcEnumPrinterDriversRequest = new rpcEnumPrinterDriversRequest();
            rpcEnumPrinterDriversRequest.pName = null;
            rpcEnumPrinterDriversRequest.pEnvironment = "Windows x64\x00";
            rpcEnumPrinterDriversRequest.Level = 2;
            rpcEnumPrinterDriversRequest.pDrivers = new BYTE();
            rpcEnumPrinterDriversRequest.cbBuf = 0;
            rpcEnumPrinterDriversResponse rpcEnumPrinterDriversResponse;
            var status = rpc.ExecuteCall((ushort)RprnServiceOpName.RpcEnumPrinterDrivers, rpcEnumPrinterDriversRequest, out rpcEnumPrinterDriversResponse);

            rpcEnumPrinterDriversRequest.pName = null;
            rpcEnumPrinterDriversRequest.pEnvironment = "Windows x64\x00";
            rpcEnumPrinterDriversRequest.Level = 2;
            rpcEnumPrinterDriversRequest.pDrivers = new BYTE((int)rpcEnumPrinterDriversResponse.pcbNeeded);
            rpcEnumPrinterDriversRequest.cbBuf = rpcEnumPrinterDriversResponse.pcbNeeded;
            status = rpc.ExecuteCall((ushort)RprnServiceOpName.RpcEnumPrinterDrivers, rpcEnumPrinterDriversRequest, out rpcEnumPrinterDriversResponse);

            return status;
        }

        public static NTStatus rpcAddPrinterDriverEx(RPCCallHelper rpc)
        {
            RpcAddPrinterDriverExRequest RpcAddPrinterDriverExRequest = new RpcAddPrinterDriverExRequest();
            RpcAddPrinterDriverExRequest.pName = null;
            RpcAddPrinterDriverExRequest.pDriverContainer = new DRIVER_CONTAINER();
            RpcAddPrinterDriverExRequest.pDriverContainer.Level = 2;
            RpcAddPrinterDriverExRequest.pDriverContainer.info2 = new DRIVER_INFO2();
            RpcAddPrinterDriverExRequest.pDriverContainer.info2.cVersion = 3;
            RpcAddPrinterDriverExRequest.pDriverContainer.info2.pName = "test\x00";
            RpcAddPrinterDriverExRequest.pDriverContainer.info2.pEnvironment = "Windows x64\x00";
            RpcAddPrinterDriverExRequest.pDriverContainer.info2.pDriverPath = "C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_7b3eed059f4c3e41\\Amd64\\UNIDRV.DLL\x00";
            RpcAddPrinterDriverExRequest.pDriverContainer.info2.pDataFile = "C:\\Windows\\System32\\kernelbase.dll\x00";
            RpcAddPrinterDriverExRequest.pDriverContainer.info2.pConfigFile = "C:\\Windows\\System32\\kernelbase.dll\x00";
            RpcAddPrinterDriverExRequest.dwFileCopyFlags = 0x00008000;

            RpcAddPrinterDriverExResponse RpcAddPrinterDriverExResponse;

            var status = rpc.ExecuteCall((ushort)RprnServiceOpName.RpcAddPrinterDriverEx, RpcAddPrinterDriverExRequest, out RpcAddPrinterDriverExResponse);
            return status;
        }

        public static PRINTER_HANDLE rpcClosePrinter(RPCCallHelper rpc, PRINTER_HANDLE pHandle, out NTStatus status)
        {
            RpcClosePrinterRequest RpcClosePrinterRequest = new RpcClosePrinterRequest();
            RpcClosePrinterRequest.pHandle = pHandle;

            RpcClosePrinterResponse RpcClosePrinterResponse;

            status = rpc.ExecuteCall((ushort)RprnServiceOpName.RpcClosePrinter, RpcClosePrinterRequest, out RpcClosePrinterResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return RpcClosePrinterResponse.pHandle;
        }
    }
}