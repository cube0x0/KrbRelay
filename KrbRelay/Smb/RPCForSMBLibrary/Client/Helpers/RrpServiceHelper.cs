using SMBLibrary.Client.Helpers;
using SMBLibrary.Services;

namespace SMBLibrary.Client
{
    public class RrpServiceHelper
    {
        public static RPC_HKEY OpenLocalMachine(RPCCallHelper rpc, out NTStatus status)
        {
            OpenLocalMachineRequest openLocalMachineRequest = new OpenLocalMachineRequest();
            openLocalMachineRequest.ServerName = null;
            openLocalMachineRequest.samDesired = REGSAM.MAXIMUM_ALLOWED | REGSAM.KEY_WOW64_32KEY | REGSAM.KEY_ENUMERATE_SUB_KEYS;

            OpenLocalMachineResponse openLocalMachineResponse;

            status = rpc.ExecuteCall((ushort)RrpServiceOpName.OpenLocalMachine, openLocalMachineRequest, out openLocalMachineResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return openLocalMachineResponse.phKey;
        }

        public static RPC_HKEY BaseRegCloseKey(RPCCallHelper rpc, RPC_HKEY hKey, out NTStatus status)
        {
            baseRegCloseKeyRequest baseRegCloseKeyRequest = new baseRegCloseKeyRequest();
            baseRegCloseKeyRequest.hKey = hKey;

            baseRegCloseKeyResponse baseRegCloseKeyResponse;

            status = rpc.ExecuteCall((ushort)RrpServiceOpName.BaseRegCloseKey, baseRegCloseKeyRequest, out baseRegCloseKeyResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return baseRegCloseKeyResponse.hKey;
        }

        public static RPC_HKEY BaseRegOpenKey(RPCCallHelper rpc, RPC_HKEY hKey, string path, out NTStatus status)
        {
            baseRegOpenKeyRequest baseRegOpenKeyRequest = new baseRegOpenKeyRequest();
            baseRegOpenKeyRequest.hKey = hKey;
            baseRegOpenKeyRequest.lpSubKey = new RPC_UNICODE_STRING(path);
            baseRegOpenKeyRequest.dwOptions = 0x00000001;
            baseRegOpenKeyRequest.samDesired = REGSAM.MAXIMUM_ALLOWED;

            baseRegOpenKeyResponse baseRegOpenKeyResponse;

            status = rpc.ExecuteCall((ushort)RrpServiceOpName.BaseRegOpenKey, baseRegOpenKeyRequest, out baseRegOpenKeyResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return baseRegOpenKeyResponse.phkResult;
        }

        public static baseRegQueryInfoKeyResponse baseRegQueryInfoKey(RPCCallHelper rpc, RPC_HKEY bKey, out NTStatus status)
        {
            baseRegQueryInfoKeyRequest baseRegQueryInfoKeyRequest = new baseRegQueryInfoKeyRequest();
            baseRegQueryInfoKeyRequest.hKey = bKey;
            baseRegQueryInfoKeyRequest.lpClassIn = new RPC_UNICODE_STRING2();
            baseRegQueryInfoKeyRequest.lpClassIn.MaximumLength = 1024;

            baseRegQueryInfoKeyResponse baseRegQueryInfoKeyResponse;

            status = rpc.ExecuteCall((ushort)RrpServiceOpName.BaseRegQueryInfoKey, baseRegQueryInfoKeyRequest, out baseRegQueryInfoKeyResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return baseRegQueryInfoKeyResponse;
        }

        public static baseRegQueryValueResponse BaseRegQueryValue(RPCCallHelper rpc, RPC_HKEY bKey, string key, out NTStatus status, uint dataLen = 512)
        {
            baseRegQueryValueRequest baseRegQueryValueRequest = new baseRegQueryValueRequest();
            baseRegQueryValueRequest.dataLen = dataLen;
            baseRegQueryValueRequest.hKey = bKey;
            baseRegQueryValueRequest.lpValueName = new RPC_UNICODE_STRING(key);
            baseRegQueryValueRequest.lpType = new LPDWORD(0);
            baseRegQueryValueRequest.lpData = new BYTE((int)dataLen);
            baseRegQueryValueRequest.lpcbData = new LPDWORD(dataLen);
            baseRegQueryValueRequest.lpcbLen = new LPDWORD(dataLen);

            baseRegQueryValueResponse baseRegQueryValueResponse;

            status = rpc.ExecuteCall((ushort)RrpServiceOpName.BaseRegQueryValue, baseRegQueryValueRequest, out baseRegQueryValueResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return baseRegQueryValueResponse;
        }

        public static RPC_HKEY BaseRegCreateKey(RPCCallHelper rpc, RPC_HKEY bKey, string key, out NTStatus status)
        {
            uint REG_CREATED_NEW_KEY = 0x00000001;
            uint REG_OPENED_EXISTING_KEY = 0x00000002;

            baseRegCreateKeyRequest baseRegCreateKeyRequest = new baseRegCreateKeyRequest();
            baseRegCreateKeyRequest.hKey = bKey;
            baseRegCreateKeyRequest.lpSubKey = new RPC_UNICODE_STRING(key);
            baseRegCreateKeyRequest.lpClass = new RPC_UNICODE_STRING();
            baseRegCreateKeyRequest.dwOptions = 0x00000001;
            baseRegCreateKeyRequest.samDesired = REGSAM.MAXIMUM_ALLOWED;
            baseRegCreateKeyRequest.lpSecurityAttributes = new RPC_SECURITY_ATTRIBUTES();
            baseRegCreateKeyRequest.lpSecurityAttributes.RpcSecurityDescriptor = new RPC_SECURITY_DESCRIPTOR();
            baseRegCreateKeyRequest.lpdwDisposition = new LPDWORD(REG_OPENED_EXISTING_KEY);

            baseRegCreateKeyResponse baseRegCreateKeyResponse;

            status = rpc.ExecuteCall((ushort)RrpServiceOpName.BaseRegCreateKey, baseRegCreateKeyRequest, out baseRegCreateKeyResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return baseRegCreateKeyResponse.phkResult;
        }

        public static NTStatus BaseRegSaveKey(RPCCallHelper rpc, RPC_HKEY bKey, string outfile)
        {
            baseRegSaveKeyRequest baseRegSaveKeyRequest = new baseRegSaveKeyRequest();
            baseRegSaveKeyRequest.hKey = bKey;
            baseRegSaveKeyRequest.lpFile = new RPC_UNICODE_STRING(outfile);
            baseRegSaveKeyRequest.pSecurityAttributes = new RPC_SECURITY_ATTRIBUTES();

            baseRegSaveKeyResponse baseRegSaveKeyResponse;

            var status = rpc.ExecuteCall((ushort)RrpServiceOpName.BaseRegSaveKey, baseRegSaveKeyRequest, out baseRegSaveKeyResponse);

            return status;
        }
    }
}