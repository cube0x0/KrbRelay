using SMBLibrary.Client.Helpers;
using SMBLibrary.Services;
using static SMBLibrary.Services.SERVICE_ENUM;

namespace SMBLibrary.Client
{
    public class ScmrServiceHelper
    {
        public static LPSC_RPC_HANDLE rOpenSCManagerW(RPCCallHelper rpc, out NTStatus status, string lpDatabaseName = "ServicesActive\x00")
        {
            ROpenSCManagerWRequest rOpenSCManagerWRequest = new ROpenSCManagerWRequest();
            rOpenSCManagerWRequest.lpDatabaseName = lpDatabaseName;
            rOpenSCManagerWRequest.dwDesiredAccess = SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SC_MANAGER_ENUMERATE_SERVICE;

            ROpenSCManagerWResponse rOpenSCManagerWResponse;

            status = rpc.ExecuteCall((ushort)ScmrServiceOpName.rOpenSCManagerW, rOpenSCManagerWRequest, out rOpenSCManagerWResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return rOpenSCManagerWResponse.lpScHandle;
        }

        public static LPSC_RPC_HANDLE rCloseServiceHandle(RPCCallHelper rpc, LPSC_RPC_HANDLE handle, out NTStatus status)
        {
            rCloseServiceHandleRequest rCloseServiceHandleRequest = new rCloseServiceHandleRequest();
            rCloseServiceHandleRequest.hSCObject = handle;

            rCloseServiceHandleResponse rCloseServiceHandleResponse;

            status = rpc.ExecuteCall((ushort)ScmrServiceOpName.rCloseServiceHandle, rCloseServiceHandleRequest, out rCloseServiceHandleResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return rCloseServiceHandleResponse.hSCObject;
        }

        public static LPSC_RPC_HANDLE rOpenServiceW(RPCCallHelper rpc, LPSC_RPC_HANDLE handle, string service, out NTStatus status)
        {
            rOpenServiceWRequest rOpenServiceWRequest = new rOpenServiceWRequest();
            rOpenServiceWRequest.hSCManager = handle;
            rOpenServiceWRequest.lpServiceName = service;
            rOpenServiceWRequest.dwDesiredAccess = SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SC_MANAGER_ENUMERATE_SERVICE;

            rOpenServiceWResponse rOpenServiceWResponse;

            status = rpc.ExecuteCall((ushort)ScmrServiceOpName.rOpenServiceW, rOpenServiceWRequest, out rOpenServiceWResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return rOpenServiceWResponse.lpServiceHandle;
        }

        public static LPSC_RPC_HANDLE rCreateServiceW(RPCCallHelper rpc, LPSC_RPC_HANDLE handle, string name, string cmd, out NTStatus status, SERIVCE_STARTUP startup = SERIVCE_STARTUP.SERVICE_DEMAND_START)
        {
            RCreateServiceWRequest RCreateServiceWRequest = new RCreateServiceWRequest();
            RCreateServiceWRequest.lpScHandle = handle;
            RCreateServiceWRequest.lpServiceName = name;
            RCreateServiceWRequest.lpDisplayName = name;
            RCreateServiceWRequest.dwDesiredAccess = (uint)SERVICE_ALL_ACCESS;
            RCreateServiceWRequest.dwServiceType = 0x00000010; // SERVICE_WIN32_OWN_PROCESS
            RCreateServiceWRequest.dwStartType = startup; // SERVICE_AUTO_START
            RCreateServiceWRequest.dwErrorControl = 0x00000000;
            RCreateServiceWRequest.lpBinaryPathName = cmd;
            RCreateServiceWRequest.lpLoadOrderGroup = null;
            RCreateServiceWRequest.lpdwTagId = 0;
            RCreateServiceWRequest.lpDependencies = null;
            RCreateServiceWRequest.dwDependSize = 0;
            RCreateServiceWRequest.lpServiceStartName = null;
            RCreateServiceWRequest.lpPassword = null;
            RCreateServiceWRequest.dwPwSize = 0;

            RCreateServiceWResponse rOpenServiceWResponse;

            status = rpc.ExecuteCall((ushort)ScmrServiceOpName.rCreateServiceW, RCreateServiceWRequest, out rOpenServiceWResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return rOpenServiceWResponse.lpScHandle;
        }

        public static NTStatus rStartServiceW(RPCCallHelper rpc, LPSC_RPC_HANDLE handle, uint argc = 0, string argv = null)
        {
            rStartServiceWRequest rStartServiceWRequest = new rStartServiceWRequest();
            rStartServiceWRequest.hService = handle;
            rStartServiceWRequest.argc = argc;
            rStartServiceWRequest.argv = argv;

            rStartServiceWResponse rStartServiceWResponse;

            var status = rpc.ExecuteCall((ushort)ScmrServiceOpName.rStartServiceW, rStartServiceWRequest, out rStartServiceWResponse);
            return status;
        }

        public static SERVICE_STATUS rControlService(RPCCallHelper rpc, LPSC_RPC_HANDLE handle, uint dwControl, out NTStatus status)
        {
            rControlServiceRequest rControlServiceRequest = new rControlServiceRequest();
            rControlServiceRequest.hService = handle;
            rControlServiceRequest.dwControl = dwControl;

            rControlServiceResponse rControlServiceResponse;

            status = rpc.ExecuteCall((ushort)ScmrServiceOpName.rControlService, rControlServiceRequest, out rControlServiceResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return rControlServiceResponse.lpServiceStatus;
        }

        public static SERVICE_STATUS rQueryServiceStatus(RPCCallHelper rpc, LPSC_RPC_HANDLE handle, out NTStatus status)
        {
            rQueryServiceStatusRequest rQueryServiceStatusRequest = new rQueryServiceStatusRequest();
            rQueryServiceStatusRequest.hService = handle;

            rQueryServiceStatusResponse rQueryServiceStatusResponse;

            status = rpc.ExecuteCall((ushort)ScmrServiceOpName.rQueryServiceStatus, rQueryServiceStatusRequest, out rQueryServiceStatusResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return rQueryServiceStatusResponse.lpServiceStatus;
        }

        public static QUERY_SERVICE_CONFIGW rQueryServiceConfig(RPCCallHelper rpc, LPSC_RPC_HANDLE handle, out NTStatus status)
        {
            rQueryServiceConfigWRequest rQueryServiceConfigWRequest = new rQueryServiceConfigWRequest();
            rQueryServiceConfigWRequest.hService = handle;
            rQueryServiceConfigWRequest.cbBufSize = 0;

            rQueryServiceConfigWResponse rQueryServiceConfigWResponse;

            status = rpc.ExecuteCall((ushort)ScmrServiceOpName.rQueryServiceConfigW, rQueryServiceConfigWRequest, out rQueryServiceConfigWResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return rQueryServiceConfigWResponse.lpServiceConfig;
        }

        public static uint rChangeServiceConfig(RPCCallHelper rpc, LPSC_RPC_HANDLE handle, out NTStatus status, SERIVCE_STARTUP startup = SERIVCE_STARTUP.SERVICE_DEMAND_START)
        {
            rChangeServiceConfigWRequest rChangeServiceConfigWRequest = new rChangeServiceConfigWRequest();
            rChangeServiceConfigWRequest.lpScHandle = handle;
            rChangeServiceConfigWRequest.dwServiceType = 0xffffffff;
            rChangeServiceConfigWRequest.dwStartType = startup;
            rChangeServiceConfigWRequest.dwErrorControl = 0xffffffff;
            rChangeServiceConfigWRequest.lpBinaryPathName = null;
            rChangeServiceConfigWRequest.lpLoadOrderGroup = null;
            rChangeServiceConfigWRequest.lpdwTagId = 0;
            rChangeServiceConfigWRequest.lpDependencies = null;
            rChangeServiceConfigWRequest.dwDependSize = 0;
            rChangeServiceConfigWRequest.lpServiceStartName = null;
            rChangeServiceConfigWRequest.lpPassword = null;
            rChangeServiceConfigWRequest.dwPwSize = 0;
            rChangeServiceConfigWRequest.lpDisplayName = null;

            rChangeServiceConfigWResponse rChangeServiceConfigWResponse;

            status = rpc.ExecuteCall((ushort)ScmrServiceOpName.rChangeServiceConfigW, rChangeServiceConfigWRequest, out rChangeServiceConfigWResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return 1;
            }
            return rChangeServiceConfigWResponse.lpdwTagId;
        }

    }
}