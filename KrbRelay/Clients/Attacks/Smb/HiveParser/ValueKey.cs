//class taken from https://github.com/brandonprry/gray_hat_csharp_code/tree/master/ch14_reading_offline_hives
using System;
using System.IO;

namespace KrbRelay.HiveParser
{
    public class ValueKey
    {
        public ValueKey(BinaryReader hive)
        {
            byte[] buf = hive.ReadBytes(2);

            if (buf[0] != 0x76 && buf[1] != 0x6b)
                throw new NotSupportedException("Bad vk header");

            NameLength = hive.ReadInt16();
            DataLength = hive.ReadInt32();

            byte[] databuf = hive.ReadBytes(4);

            ValueType = hive.ReadInt32();
            hive.BaseStream.Position += 4;

            buf = hive.ReadBytes(NameLength);
            Name = (NameLength == 0) ? "Default" : System.Text.Encoding.UTF8.GetString(buf);

            if (DataLength < 5)
                Data = databuf;
            else
            {
                hive.BaseStream.Position = 4096 + BitConverter.ToInt32(databuf, 0) + 4;
                Data = hive.ReadBytes(DataLength);
            }
        }

        public short NameLength { get; set; }
        public int DataLength { get; set; }
        public int DataOffset { get; set; }
        public int ValueType { get; set; }
        public string Name { get; set; }
        public byte[] Data { get; set; }
        public string String { get; set; }
    }
}