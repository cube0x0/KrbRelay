using SMBLibrary.RPC;
using System;

namespace SMBLibrary.Services
{
    public class SAMPR_ENUMERATION_BUFFER : INDRStructure
    {
        public uint EntriesRead;
        public NDRConformantArray<SAMPR_RID_ENUMERATION> Buffer;

        public void Read(NDRParser parser)
        {
            EntriesRead = parser.ReadUInt32();
            Buffer = new NDRConformantArray<SAMPR_RID_ENUMERATION>();
            parser.ReadStructure(Buffer);
        }

        public void Write(NDRWriter writer)
        {
            throw new NotImplementedException();
            //writer.BeginStructure();
            //writer.WriteUInt32(EntriesRead);
            //writer.WriteStructure(Buffer);
            //writer.EndStructure();
        }
    }
}