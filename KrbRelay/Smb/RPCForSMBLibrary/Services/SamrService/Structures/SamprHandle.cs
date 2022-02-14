using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class SamprHandle : INDRStructure
    {
        //This is a RPC handle ( context_handle ), serialized into 20 bytes

        private uint part1;
        private uint part2;
        private uint part3;
        private uint part4;
        private uint part5;

        public void Read(NDRParser parser)
        {
            part1 = parser.ReadUInt32();
            part2 = parser.ReadUInt32();
            part3 = parser.ReadUInt32();
            part4 = parser.ReadUInt32();
            part5 = parser.ReadUInt32();
        }

        public void Write(NDRWriter writer)
        {
            writer.WriteUInt32(part1);
            writer.WriteUInt32(part2);
            writer.WriteUInt32(part3);
            writer.WriteUInt32(part4);
            writer.WriteUInt32(part5);
        }
    }
}