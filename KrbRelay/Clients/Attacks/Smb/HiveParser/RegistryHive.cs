//class from https://github.com/brandonprry/gray_hat_csharp_code/tree/master/ch14_reading_offline_hives
//author @BrandonPrry
using System;
using System.IO;

namespace KrbRelay.HiveParser
{
    public class RegistryHive
    {
        public static RegistryHive ImportHiveDump(string dumpfileName)
        {
            if (File.Exists(dumpfileName))
            {
                using (FileStream stream = File.OpenRead(dumpfileName))
                {
                    using (BinaryReader reader = new BinaryReader(stream))
                    {
                        reader.BaseStream.Position += 4132 - reader.BaseStream.Position;
                        RegistryHive hive = new RegistryHive(reader);
                        return hive;
                    }
                }
            }
            else
            {
                Console.WriteLine("[-] Unable to access hive dump ", dumpfileName);
                return null;
            }
        }

        public RegistryHive(BinaryReader reader)
        {
            reader.BaseStream.Position += 4132 - reader.BaseStream.Position;
            this.RootKey = new NodeKey(reader);
        }

        public string Filepath { get; set; }
        public NodeKey RootKey { get; set; }
        public bool WasExported { get; set; }
    }
}