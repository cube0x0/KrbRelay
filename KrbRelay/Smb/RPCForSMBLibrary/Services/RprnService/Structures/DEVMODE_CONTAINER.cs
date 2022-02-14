using SMBLibrary.RPC;
using System;

namespace SMBLibrary.Services
{
    public class DEVMODE_CONTAINER : INDRStructure
    {
        public uint cbBuf;
        public BYTE pDevMode;

        public void Read(NDRParser parser)
        {
            throw new NotImplementedException();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32(cbBuf);
            writer.WriteEmbeddedStructureFullPointer(pDevMode);
            writer.EndStructure();
        }
    }
}