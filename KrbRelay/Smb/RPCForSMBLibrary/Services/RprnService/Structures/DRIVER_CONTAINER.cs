using SMBLibrary.RPC;
using System;

namespace SMBLibrary.Services
{
    public class DRIVER_CONTAINER : INDRStructure
    {
        public uint Level;
        public DRIVER_INFO2 info2;

        public void Read(NDRParser parser)
        {
            throw new NotImplementedException();
        }

        public void Write(NDRWriter writer)
        {
            writer.WriteUInt32(Level);
            switch (Level)
            {
                case 2:
                    //writer.BeginStructure(); // DRIVER_INFO2
                    writer.WriteUInt32(2);
                    writer.WriteStructure(info2);
                    //writer.EndStructure();
                    break;

                default:
                    throw new NotImplementedException();
            }
        }
    }
}