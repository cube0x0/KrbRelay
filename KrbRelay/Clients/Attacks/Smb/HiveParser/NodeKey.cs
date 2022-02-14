//class from https://github.com/brandonprry/gray_hat_csharp_code/tree/master/ch14_reading_offline_hives
//author @BrandonPrry
using System;
using System.Collections.Generic;
using System.IO;

namespace KrbRelay.HiveParser
{
    public class NodeKey
    {
        public NodeKey(BinaryReader hive)
        {
            ReadNodeStructure(hive);
            ReadChildrenNodes(hive);
            ReadChildValues(hive);
        }

        public List<NodeKey> ChildNodes { get; set; }
        public List<ValueKey> ChildValues { get; set; }
        public DateTime Timestamp { get; set; }
        public int ParentOffset { get; set; }
        public int SubkeysCount { get; set; }
        public int LFRecordOffset { get; set; }
        public int ClassnameOffset { get; set; }
        public int SecurityKeyOffset { get; set; }
        public int ValuesCount { get; set; }
        public int ValueListOffset { get; set; }
        public short NameLength { get; set; }
        public bool IsRootKey { get; set; }
        public short ClassnameLength { get; set; }
        public string Name { get; set; }
        public byte[] ClassnameData { get; set; }
        public NodeKey ParentNodeKey { get; set; }

        private void ReadNodeStructure(BinaryReader hive)
        {
            byte[] buf = hive.ReadBytes(4);

            if (buf[0] != 0x6e || buf[1] != 0x6b)
                throw new NotSupportedException("Bad nk header");

            long startingOffset = hive.BaseStream.Position;
            this.IsRootKey = (buf[2] == 0x2c) ? true : false;

            this.Timestamp = DateTime.FromFileTime(hive.ReadInt64());

            hive.BaseStream.Position += 4;

            this.ParentOffset = hive.ReadInt32();
            this.SubkeysCount = hive.ReadInt32();

            hive.BaseStream.Position += 4;

            this.LFRecordOffset = hive.ReadInt32();

            hive.BaseStream.Position += 4;

            this.ValuesCount = hive.ReadInt32();
            this.ValueListOffset = hive.ReadInt32();
            this.SecurityKeyOffset = hive.ReadInt32();
            this.ClassnameOffset = hive.ReadInt32();

            hive.BaseStream.Position += (startingOffset + 68) - hive.BaseStream.Position;

            this.NameLength = hive.ReadInt16();
            this.ClassnameLength = hive.ReadInt16();

            buf = hive.ReadBytes(this.NameLength);
            this.Name = System.Text.Encoding.UTF8.GetString(buf);

            hive.BaseStream.Position = this.ClassnameOffset + 4 + 4096;
            this.ClassnameData = hive.ReadBytes(this.ClassnameLength);
        }

        private void ReadChildrenNodes(BinaryReader hive)
        {
            this.ChildNodes = new List<NodeKey>();
            if (this.LFRecordOffset != -1)
            {
                hive.BaseStream.Position = 4096 + this.LFRecordOffset + 4;

                byte[] buf = hive.ReadBytes(2);

                //ri
                if (buf[0] == 0x72 && buf[1] == 0x69)
                {
                    int count = hive.ReadInt16();

                    for (int i = 0; i < count; i++)
                    {
                        long pos = hive.BaseStream.Position;
                        int offset = hive.ReadInt32();
                        hive.BaseStream.Position = 4096 + offset + 4;
                        buf = hive.ReadBytes(2);

                        if (!(buf[0] == 0x6c && (buf[1] == 0x66 || buf[1] == 0x68)))
                            throw new Exception("Bad LF/LH record at: " + hive.BaseStream.Position);

                        ParseChildNodes(hive);

                        hive.BaseStream.Position = pos + 4; //go to next record list
                    }
                }
                //lf or lh
                else if (buf[0] == 0x6c && (buf[1] == 0x66 || buf[1] == 0x68))
                    ParseChildNodes(hive);
                else
                    throw new Exception("Bad LF/LH/RI Record at: " + hive.BaseStream.Position);
            }
        }

        private void ParseChildNodes(BinaryReader hive)
        {
            int count = hive.ReadInt16();
            long topOfList = hive.BaseStream.Position;

            for (int i = 0; i < count; i++)
            {
                hive.BaseStream.Position = topOfList + (i * 8);
                int newoffset = hive.ReadInt32();
                hive.BaseStream.Position += 4;
                //byte[] check = hive.ReadBytes(4);
                hive.BaseStream.Position = 4096 + newoffset + 4;
                NodeKey nk = new NodeKey(hive) { ParentNodeKey = this };
                this.ChildNodes.Add(nk);
            }

            hive.BaseStream.Position = topOfList + (count * 8);
        }

        private void ReadChildValues(BinaryReader hive)
        {
            this.ChildValues = new List<ValueKey>();
            if (this.ValueListOffset != -1)
            {
                hive.BaseStream.Position = 4096 + this.ValueListOffset + 4;

                for (int i = 0; i < this.ValuesCount; i++)
                {
                    hive.BaseStream.Position = 4096 + this.ValueListOffset + 4 + (i * 4);
                    int offset = hive.ReadInt32();
                    hive.BaseStream.Position = 4096 + offset + 4;
                    this.ChildValues.Add(new ValueKey(hive));
                }
            }
        }

        public byte[] getChildValues(string valueName)
        {
            ValueKey targetData = this.ChildValues.Find(x => x.Name.Contains(valueName));
            return targetData.Data;
        }
    }
}