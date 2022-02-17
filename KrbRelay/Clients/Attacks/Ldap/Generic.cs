using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace KrbRelay.Clients.Attacks.Ldap
{
    internal class Generic
    {
        private static string DecodeASCIIOrUnicode(IntPtr ptr)
        {
            if (Marshal.ReadByte(ptr + 1) == 0x00)
            {
                return Marshal.PtrToStringUni(ptr);
            }
            else
            {
                return Marshal.PtrToStringAnsi(ptr);
            }
        }

        private static string DecodeASCIIOrUnicode(byte[] bytes)
        {
            if (bytes[1] == 0x00)
            {
                return Encoding.Unicode.GetString(bytes);
            }
            else
            {
                return Encoding.ASCII.GetString(bytes);
            }
        }

        public static string GetDistinguishedName(IntPtr ld, IntPtr entry)
        {
            var ptr = Interop.ldap_get_dn(ld, entry);
            return DecodeASCIIOrUnicode(ptr);
        }

        public static string GetDistinguishedName(IntPtr ld, string filter) {
            var timeout = new LDAP_TIMEVAL
            {
                tv_sec = (int)(new TimeSpan(0, 0, 30).Ticks / TimeSpan.TicksPerSecond)
            };
            IntPtr pLaps = Helpers.AllocHGlobalIntPtrArray(1 + 1);
            var controlPtr = Marshal.StringToHGlobalUni("DistinguishedName");
            Marshal.WriteIntPtr(pLaps, IntPtr.Size * 0, controlPtr);

            var search = Interop.ldap_search(
                ld,
                State.domainDN,
                (int)LdapSearchScope.SubTree,
                filter,
                pLaps,
                0
            );

            IntPtr pMessage = IntPtr.Zero;
            var r = Interop.ldap_result(ld, search, 0, timeout, ref pMessage);
            var entry = Interop.ldap_first_entry(ld, pMessage);
            IntPtr ber = IntPtr.Zero;

            var attr = Interop.ldap_first_attribute(ld, entry, ref ber);
            var vals = Interop.ldap_get_values_len(ld, entry, attr);
            var attrName = Marshal.PtrToStringUni(attr);

            var result = new List<byte[]>();
            foreach (var tempPtr in Helpers.GetPointerArray(vals))
            {
                berval bervalue = (berval)Marshal.PtrToStructure(
                    tempPtr,
                    typeof(berval)
                );
                if (bervalue.bv_len > 0 && bervalue.bv_val != IntPtr.Zero)
                {
                    var byteArray = new byte[bervalue.bv_len];
                    Marshal.Copy(bervalue.bv_val, byteArray, 0, bervalue.bv_len);
                    result.Add(byteArray);
                }
            }
            byte[] t = result.SelectMany(a => a).ToArray();
            //Console.WriteLine("[+] {0}: {1}", attribute, Encoding.ASCII.GetString(t));

            Marshal.FreeHGlobal(controlPtr);
            string dn = Encoding.ASCII.GetString(t);

            if (String.IsNullOrEmpty(dn))
            {
                throw new InvalidOperationException("DN was empty");
            }

            return dn;
        }

        public static string GetDistinguishedNameFromAccountName(IntPtr ld, string samAccountName, bool treatAsMachine = true)
        {
            if (string.IsNullOrEmpty(samAccountName))
            {
                if (treatAsMachine)
                {
                    samAccountName = Environment.MachineName;
                } else
                {
                    samAccountName = Environment.UserName;
                }
            }

            if (treatAsMachine && !samAccountName.EndsWith("$"))
            {
                samAccountName += "$";
            }

            return GetDistinguishedName(ld, String.Format("(&(objectClass=*)(sAMAccountName={0}))", samAccountName));
        }

        public static string GetDistinguishedNameFromSid(IntPtr ld, string sid)
        {
            return GetDistinguishedName(ld, String.Format("(&(objectClass=*)(objectSID={0}))", sid));
        }

        public static LdapStatus SetAttribute(IntPtr ld, string distinguishedName, string attribute, byte[] value)
        {
            return ModifyAttribute(ld, LdapModOperation.Replace, distinguishedName, attribute, new List<byte[]> { value });
        }

        public static LdapStatus AddAttribute(IntPtr ld, string distinguishedName, string attribute, byte[] value)
        {
            return ModifyAttribute(ld, LdapModOperation.Add, distinguishedName, attribute, new List<byte[]> { value });
        }

        public static LdapStatus RemoveAttribute(IntPtr ld, string distinguishedName, string attribute, byte[] value)
        {
            return ModifyAttribute(ld, LdapModOperation.Delete, distinguishedName, attribute, new List<byte[]> { value });
        }

        private static LdapStatus ModifyAttribute(IntPtr ld, LdapModOperation operation, string distinguishedName, string attribute, List<byte[]> values)
        {
            var modPropPtr = Marshal.StringToHGlobalUni(attribute);
            var modValuePtr = Marshal.AllocHGlobal(IntPtr.Size * 2);
            Helpers.ByteArraysToBerValueArray(
                values.Select(_ => _ ?? new byte[0]).ToArray(),
                modValuePtr
            );

            List<LDAPMod> mod = new List<LDAPMod>
            {
                new LDAPMod
                {
                    mod_op =
                        (int)operation | (int)LdapModOperation.BValues,
                    mod_type = modPropPtr,
                    mod_vals_u = new LDAPMod.mod_vals { modv_bvals = modValuePtr },
                    mod_next = IntPtr.Zero
                }
            };
            var ptr = Marshal.AllocHGlobal(IntPtr.Size * 2); // alloc memory for list with last element null
            Helpers.StructureArrayToPtr(mod, ptr, true);

            //int rest = ldap_modify_ext(ld, dn, ptr, IntPtr.Zero, IntPtr.Zero, out int pMessage);
            int rest = Interop.ldap_modify(ld, distinguishedName, ptr);
            Console.WriteLine("[*] ldap_modify: {0}", (LdapStatus)rest);

            mod.ForEach(
                _ =>
                {
                    Helpers.BerValuesFree(_.mod_vals_u.modv_bvals);
                    Marshal.FreeHGlobal(_.mod_vals_u.modv_bvals);
                    Marshal.FreeHGlobal(_.mod_type);
                }
            );
            Marshal.FreeHGlobal(ptr);

            return (LdapStatus)rest;
        }

        public static Dictionary<string, List<byte[]>> GetAttributes(IntPtr ld,IntPtr entry,ref IntPtr ber)
        {
            Dictionary<string, List<byte[]>> list = new Dictionary<string, List<byte[]>>();
            for (
                var attr = Interop.ldap_first_attribute(ld, entry, ref ber);
                attr != IntPtr.Zero;
                attr = Interop.ldap_next_attribute(ld, entry, ber)
            )
            {
                var vals = Interop.ldap_get_values_len(ld, entry, attr);
                if (vals != IntPtr.Zero)
                {
                    var attrName = Marshal.PtrToStringUni(attr);
                    if (attrName != null)
                    {
                        list.Add(attrName, Helpers.BerValArrayToByteArrays(vals));
                    }
                    Interop.ldap_value_free_len(vals);
                }
            }
            return list;
        }

        public static List<IntPtr> GetObjects(IntPtr ld, string distinguishedName, string filter, string attribute = null)
        {
            var timeout = new LDAP_TIMEVAL
            {
                tv_sec = (int)(new TimeSpan(0, 0, 30).Ticks / TimeSpan.TicksPerSecond)
            };

            var pLaps = Helpers.AllocHGlobalIntPtrArray(1 + 1);
            var controlPtr = IntPtr.Zero;
            if (attribute != null)
            {
                controlPtr = Marshal.StringToHGlobalUni(attribute);
                Marshal.WriteIntPtr(pLaps, IntPtr.Size * 0, controlPtr);
            }

            var search = Interop.ldap_search(
                ld,
                distinguishedName,
                (int)LdapSearchScope.SubTree,
                filter,
                pLaps,
                0
            );

            IntPtr pMessage = IntPtr.Zero;
            Interop.ldap_result(ld, search, 1, timeout, ref pMessage);

            List<IntPtr> result = new List<IntPtr>();
            for (
                var entry = Interop.ldap_first_entry(ld, pMessage);
                entry != IntPtr.Zero;
                entry = Interop.ldap_next_entry(ld, entry)
            )
            {
                result.Add(entry);
            }
            
            if (controlPtr != IntPtr.Zero)
                Marshal.FreeHGlobal(controlPtr);

            return result;
        }

        public static List<byte[]> GetAttributeRaw(IntPtr ld, string distinguishedName, string filter, string attribute)
        {
            var timeout = new LDAP_TIMEVAL
            {
                tv_sec = (int)(new TimeSpan(0, 0, 30).Ticks / TimeSpan.TicksPerSecond)
            };
            IntPtr pLaps = Helpers.AllocHGlobalIntPtrArray(1 + 1);
            var controlPtr = Marshal.StringToHGlobalUni(attribute);
            Marshal.WriteIntPtr(pLaps, IntPtr.Size * 0, controlPtr);

            var search = Interop.ldap_search(
                ld,
                distinguishedName,
                (int)LdapSearchScope.SubTree,
                filter,
                pLaps,
                0
            );

            IntPtr pMessage = IntPtr.Zero;
            var r = Interop.ldap_result(ld, search, 0, timeout, ref pMessage);
            var entry = Interop.ldap_first_entry(ld, pMessage);

            IntPtr ber = IntPtr.Zero;
            var attr = Interop.ldap_first_attribute(ld, entry, ref ber);
            var vals = Interop.ldap_get_values_len(ld, entry, attr);

            var result = new List<byte[]>();
            foreach (var tempPtr in Helpers.GetPointerArray(vals))
            {
                berval bervalue = Marshal.PtrToStructure<berval>(tempPtr);
                if (bervalue.bv_len > 0 && bervalue.bv_val != IntPtr.Zero)
                {
                    var byteArray = new byte[bervalue.bv_len];
                    Marshal.Copy(bervalue.bv_val, byteArray, 0, bervalue.bv_len);
                    result.Add(byteArray);
                }
            }

            Marshal.FreeHGlobal(controlPtr);
            return result;
        }

        public static List<byte[]> GetAttribute(IntPtr ld, string distinguishedName, string attribute)
        {
            return GetAttributeRaw(ld, distinguishedName, "(objectClass=*)", attribute);
        }

        public static List<byte[]> GetAttributeWithAccountName(IntPtr ld, string samAccountName, string attribute)
        {
            return GetAttributeRaw(ld, State.domainDN, String.Format("(&(sAMAccountName={0}))", samAccountName), attribute);
        }

        public static string GetAttributeAsString(IntPtr ld, string distinguishedName, string attribute)
        {
            List<byte[]> result = GetAttribute(ld, distinguishedName, attribute);
            byte[] flat = result.SelectMany(a => a).ToArray();
            return DecodeASCIIOrUnicode(flat);
        }

        public static string GetAttributeWithAccountNameAsString(IntPtr ld, string samAccountName, string attribute)
        {
            List<byte[]> result = GetAttributeWithAccountName(ld, samAccountName, attribute);
            byte[] flat = result.SelectMany(a => a).ToArray();
            return DecodeASCIIOrUnicode(flat);
        }
    }
}
