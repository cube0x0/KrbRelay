using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class QUERY_SERVICE_CONFIGW : INDRStructure
    {
        //This is a RPC handle ( context_handle ), serialized into 20 bytes

        public uint dwServiceType;
        public uint dwStartType;
        public uint dwErrorControl;
        public string lpBinaryPathName;
        public string lpLoadOrderGroup;
        public uint dwTagId;
        public string lpDependencies;
        public string lpServiceStartName;
        public string lpDisplayName;

        public void Read(NDRParser parser)
        {
            dwServiceType = parser.ReadUInt32();
            dwStartType = parser.ReadUInt32();
            dwErrorControl = parser.ReadUInt32();
            lpBinaryPathName = parser.ReadTopLevelUnicodeStringPointer();
            lpLoadOrderGroup = parser.ReadTopLevelUnicodeStringPointer();
            dwTagId = parser.ReadUInt32();
            lpDependencies = parser.ReadTopLevelUnicodeStringPointer();
            lpServiceStartName = parser.ReadTopLevelUnicodeStringPointer();
            lpDisplayName = parser.ReadTopLevelUnicodeStringPointer();
        }

        public void Write(NDRWriter writer)
        {
            writer.WriteUInt32(dwServiceType);
            writer.WriteUInt32(dwStartType);
            writer.WriteUInt32(dwErrorControl);
            writer.WriteUnicodeString(lpBinaryPathName);
            writer.WriteUnicodeString(lpLoadOrderGroup);
            writer.WriteUInt32(dwTagId);
            writer.WriteUnicodeString(lpDependencies);
            writer.WriteUnicodeString(lpServiceStartName);
            writer.WriteUnicodeString(lpDisplayName);
        }
    }
}