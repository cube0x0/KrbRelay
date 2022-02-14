using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class SAMPR_RID_ENUMERATION : INDRStructure
    {
        public uint RelativeId;
        public NDRUnicodeString Name;

        public void Read(NDRParser parser)
        {
            RelativeId = parser.ReadUInt32();
            Name = new NDRUnicodeString();
            parser.ReadStructure(Name);
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32(RelativeId);
            writer.WriteStructure(Name);
            writer.EndStructure();
        }
    }
}