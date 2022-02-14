using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class TASK_XML_ERROR_INFO : INDRStructure
    {
        public uint line;
        public uint column;
        public string node;
        public string value;

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            line = parser.ReadUInt32();
            column = parser.ReadUInt32();
            node = parser.ReadUnicodeString();
            value = parser.ReadUnicodeString();
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32(line);
            writer.WriteUInt32(column);
            writer.WriteUnicodeString(node);
            writer.WriteUnicodeString(value);
            writer.EndStructure();
        }
    }
}