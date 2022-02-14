using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class RPC_SECURITY_ATTRIBUTES : INDRStructure
    {
        public uint nLength;
        public RPC_SECURITY_DESCRIPTOR RpcSecurityDescriptor;
        public bool bInheritHandle;

        public void Read(NDRParser parser)
        {
            nLength = parser.ReadUInt32();
            RpcSecurityDescriptor = new RPC_SECURITY_DESCRIPTOR();
            parser.ReadStructure(RpcSecurityDescriptor);
            //writer.WriteUInt16((short)bInheritHandle);
        }

        public void Write(NDRWriter writer)
        {
            writer.WriteUInt32(nLength);
            //writer.WriteStructure(RpcSecurityDescriptor);
            //writer.WriteUInt16((short)bInheritHandle);
        }
    }

    public class RPC_SECURITY_DESCRIPTOR : INDRStructure
    {
        public byte[] lpSecurityDescriptor;
        public uint cbInSecurityDescriptor;
        public uint cbOutSecurityDescriptor;

        public void Read(NDRParser parser)
        {
            lpSecurityDescriptor = parser.ReadBytes(0);
            cbInSecurityDescriptor = parser.ReadUInt32();
            cbOutSecurityDescriptor = parser.ReadUInt32();
        }

        public void Write(NDRWriter writer)
        {
            writer.WriteBytes(lpSecurityDescriptor);
            writer.WriteUInt32(cbInSecurityDescriptor);
            writer.WriteUInt32(cbOutSecurityDescriptor);
        }
    }
}