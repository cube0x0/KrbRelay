using SMBLibrary.RPC;
using System;

namespace SMBLibrary.Services
{
    public class TASK_USER_CRED : INDRStructure
    {
        public string userId;
        public string password;
        public uint flags;

        public void Read(NDRParser parser)
        {
            throw new NotImplementedException();
        }

        public void Write(NDRWriter writer)
        {
            //writer.BeginStructure();
            writer.WriteTopLevelUnicodeStringPointer(userId);
            writer.WriteTopLevelUnicodeStringPointer(password);
            writer.WriteUInt32(flags);
            //writer.EndStructure();
        }
    }
}