using SMBLibrary.RPC;
using System;

namespace SMBLibrary.Services
{
    /// <summary>
    /// [MS-SAMR] SAMPR_USER_INFO_BUFFER Union
    /// </summary>
    public class SAMPR_USER_INFO_BUFFER : INDRStructure
    {
        public uint UserInformationClass;
        public SAMPR_USER_INTERNAL1_INFORMATION Internal1;

        public SAMPR_USER_INFO_BUFFER()
        {
        }

        public SAMPR_USER_INFO_BUFFER(uint level)
        {
            UserInformationClass = level;
        }

        public SAMPR_USER_INFO_BUFFER(NDRParser parser)
        {
            Read(parser);
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure(); // SAMPR_USER_INFO_BUFFER Union
            UserInformationClass = parser.ReadUInt32();
            switch (UserInformationClass)
            {
                case 18:
                    SAMPR_USER_INTERNAL1_INFORMATION buffer = new SAMPR_USER_INTERNAL1_INFORMATION();
                    parser.ReadEmbeddedStructureFullPointer<SAMPR_USER_INTERNAL1_INFORMATION>(ref buffer);
                    Internal1 = buffer;
                    break;

                default:
                    throw new NotImplementedException();
            }
            parser.EndStructure(); // SAMPR_USER_INFO_BUFFER Union
        }

        public void Write(NDRWriter writer)
        {
            switch (UserInformationClass)
            {
                case 18:
                    //writer.BeginStructure(); // SAMPR_USER_INTERNAL1_INFORMATION
                    writer.WriteStructure(Internal1);
                    //writer.EndStructure();
                    break;

                default:
                    throw new NotImplementedException();
            }
        }
    }
}