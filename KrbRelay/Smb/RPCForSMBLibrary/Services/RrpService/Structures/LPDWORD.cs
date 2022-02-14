using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class LPDWORD : INDRStructure
    {
        public uint value;

        public LPDWORD()
        {
            value = 0;
        }

        public LPDWORD(uint size)
        {
            value = size;
        }

        public void Read(NDRParser parser)
        {
            value = parser.ReadUInt32();
        }

        public void Write(NDRWriter writer)
        {
            writer.WriteUInt32(value);
        }
    }
}