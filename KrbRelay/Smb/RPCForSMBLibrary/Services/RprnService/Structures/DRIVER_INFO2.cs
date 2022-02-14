using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class DRIVER_INFO2 : INDRStructure
    {
        public uint cVersion;
        public string pName;
        public string pEnvironment;
        public string pDriverPath;
        public string pDataFile;
        public string pConfigFile;

        public void Read(NDRParser parser)
        {
            cVersion = parser.ReadUInt32();
            pName = parser.ReadUnicodeString();
            pEnvironment = parser.ReadUnicodeString();
            pDriverPath = parser.ReadUnicodeString();
            pDataFile = parser.ReadUnicodeString();
            pConfigFile = parser.ReadUnicodeString();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32(cVersion);
            writer.WriteUnicodeString(pName);
            writer.WriteUnicodeString(pEnvironment);
            writer.WriteUnicodeString(pDriverPath);
            writer.WriteUnicodeString(pDataFile);
            writer.WriteUnicodeString(pConfigFile);
            writer.EndStructure();
        }
    }
}