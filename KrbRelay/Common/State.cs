using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KrbRelay
{
    static class State
    {
        // LDAP
        public static SspiHandle ldap_CredHandle = new SspiHandle(); // Credential handle
        public static IntPtr ld = IntPtr.Zero; // Open handle for LDAP APIs

        // Relay
        public static byte[] apReq = new byte[] { };
        public static byte[] apRep1 = new byte[] { };
        public static byte[] apRep2 = new byte[] { };
        public static byte[] ticket = new byte[] { };

        // Parameters
        public static string spn = "";
        public static string relayedUser = "";
        public static string relayedUserDomain = "";
        public static string domainDN = "";
        public static string targetFQDN = "";
        public static bool useSSL = false;
        public static Dictionary<string, string> attacks = new Dictionary<string, string>();

        // Syncronization
        public static bool stopSpoofing = false;

        public static void UpdateApReq(byte[] bytes)
        {
            apReq = bytes;
            ticket = bytes;
            Console.WriteLine("[*] Got initial AP_REQ");
#if DEBUG
            Console.WriteLine(" |- {0}", Helpers.ByteArrayToHex(bytes));
#endif
        }

        public static void UpdateApRep1(byte[] bytes)
        {
            apRep1 = bytes;
            Console.WriteLine("[*] Got first AP_REP");
#if DEBUG
            Console.WriteLine(" |- {0}", Helpers.ByteArrayToHex(bytes));
#endif
        }

        public static void UpdateApRep2(byte[] bytes)
        {
            apRep2 = bytes;
            ticket = bytes;
            Console.WriteLine("[*] Got second AP_REP");
#if DEBUG
            Console.WriteLine(" |- {0}", Helpers.ByteArrayToHex(bytes));
#endif
        }
    }
}
