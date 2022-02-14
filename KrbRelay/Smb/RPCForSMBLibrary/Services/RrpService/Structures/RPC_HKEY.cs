using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class RPC_HKEY : INDRStructure
    {
        private uint context_handle_attributes;
        private GUID context_handle_uuid;

        public void Read(NDRParser parser)
        {
            context_handle_attributes = parser.ReadUInt32();
            context_handle_uuid = new GUID();
            parser.ReadStructure(context_handle_uuid);
        }

        public void Write(NDRWriter writer)
        {
            writer.WriteUInt32(context_handle_attributes);
            writer.WriteStructure(context_handle_uuid);
        }
    }
}