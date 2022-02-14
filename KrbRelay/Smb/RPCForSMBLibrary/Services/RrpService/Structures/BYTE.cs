using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class BYTE : INDRStructure
    {
        public byte[] array = new byte[] { };
        public int length;

        public BYTE()
        {
            array = new byte[] { };
        }

        public BYTE(int size)
        {
            array = new byte[size];
        }

        public void Read(NDRParser parser)
        {
            array = parser.ReadBytes(8);
        }

        public void Write(NDRWriter writer)
        {
            writer.WriteBytes(array);
            //writer.WriteUInt32((uint)array.Length);
        }
    }
}