using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class RPC_UNICODE_STRING2 : INDRStructure
    {
        public NDRUnicodeString Data;
        public uint Length;
        public uint MaximumLength;

        public RPC_UNICODE_STRING2()
        {
            Data = new NDRUnicodeString(string.Empty, false);
        }

        public RPC_UNICODE_STRING2(string value)
        {
            Data = new NDRUnicodeString(value, false);
        }

        public RPC_UNICODE_STRING2(string value, bool nullc)
        {
            Data = new NDRUnicodeString(value, nullc);
        }

        public RPC_UNICODE_STRING2(NDRParser parser) : this()
        {
            Read(parser);
        }

        public string Value
        {
            get
            {
                return Data.Value;
            }
            set
            {
                Data.Value = value;
            }
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            Length = parser.ReadUInt16();
            MaximumLength = parser.ReadUInt16();
            parser.ReadEmbeddedStructureFullPointer(ref Data);
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            ushort length = 0;
            //writer.BeginStructure();
            writer.WriteUInt16((ushort)((length) * 2));
            if(MaximumLength > 0)
                writer.WriteUInt16((ushort)MaximumLength);
            else
                writer.WriteUInt16((ushort)((length) * 2));
            writer.WriteEmbeddedStructureFullPointer(null);
            //writer.EndStructure();
        }
    }
}