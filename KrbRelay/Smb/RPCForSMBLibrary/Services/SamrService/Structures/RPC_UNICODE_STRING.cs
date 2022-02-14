using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class RPC_UNICODE_STRING : INDRStructure
    {
        public NDRUnicodeString buffer;
        public uint Length;
        public uint MaximumLength;

        public RPC_UNICODE_STRING()
        {
            buffer = new NDRUnicodeString(string.Empty, false);
        }

        public RPC_UNICODE_STRING(string value)
        {
            buffer = new NDRUnicodeString(value, false);
        }

        public RPC_UNICODE_STRING(string value, bool nullc)
        {
            buffer = new NDRUnicodeString(value, nullc);
        }

        public RPC_UNICODE_STRING(NDRParser parser) : this()
        {
            Read(parser);
        }

        public string Value
        {
            get
            {
                return buffer.Value;
            }
            set
            {
                buffer.Value = value;
            }
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            Length = parser.ReadUInt16();
            MaximumLength = parser.ReadUInt16();
            parser.ReadEmbeddedStructureFullPointer(ref buffer);
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            ushort length = 0;
            if (buffer.Value != null)
            {
                length = (ushort)buffer.Value.Length;
            }
            if (Length != 0)
            {
                length = (ushort)Length;
            }
            writer.BeginStructure();
            writer.WriteUInt16((ushort)((length) * 2));
            writer.WriteUInt16((ushort)((length) * 2));
            writer.WriteEmbeddedStructureFullPointer(buffer);
            writer.EndStructure();
        }
    }
}