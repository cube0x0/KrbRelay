using System;
using System.IO;
using System.Text;
using static KrbRelay.HiveParser.Registry;

namespace KrbRelay.HiveParser
{
    // Modified version of https://github.com/G0ldenGunSec/SharpSecDump
    public class Parse
    {
        public static void ParseSecrets(byte[] samBytes, byte[] securityBytes, byte[] systemBytes, byte[] bootKey)
        {
            StringBuilder sb = new StringBuilder();

            //using (BinaryReader systemReader = new BinaryReader(new MemoryStream(systemBytes)))
            //{
            //    // TODO system hive throws
            //    // [-] System.Exception: Bad LF/LH/RI Record at: 6324262
            //    RegistryHive system = new RegistryHive(systemReader);
            //
            //    using (BinaryReader securityReader = new BinaryReader(new MemoryStream(securityBytes)))
            //    {
            //        RegistryHive security = new RegistryHive(securityReader);
            //        ParseLsa(security, bootKey, system).ForEach(item => sb.Append(item + Environment.NewLine));
            //    }
            //}

            using (BinaryReader samReader = new BinaryReader(new MemoryStream(samBytes)))
            {
                RegistryHive sam = new RegistryHive(samReader);
                ParseSam(bootKey, sam).ForEach(item => sb.Append(item + Environment.NewLine));
            }

            Console.WriteLine(sb.ToString());
        }
    }
}