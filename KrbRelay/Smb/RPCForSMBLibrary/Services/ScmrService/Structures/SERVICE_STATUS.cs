using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class SERVICE_STATUS : INDRStructure
    {
        //This is a RPC handle ( context_handle ), serialized into 20 bytes

        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;

        public void Read(NDRParser parser)
        {
            dwServiceType = parser.ReadUInt32();
            dwCurrentState = parser.ReadUInt32();
            dwControlsAccepted = parser.ReadUInt32();
            dwWin32ExitCode = parser.ReadUInt32();
            dwServiceSpecificExitCode = parser.ReadUInt32();
            dwCheckPoint = parser.ReadUInt32();
            dwWaitHint = parser.ReadUInt32();
        }

        public void Write(NDRWriter writer)
        {
            writer.WriteUInt32(dwServiceType);
            writer.WriteUInt32(dwCurrentState);
            writer.WriteUInt32(dwControlsAccepted);
            writer.WriteUInt32(dwWin32ExitCode);
            writer.WriteUInt32(dwServiceSpecificExitCode);
            writer.WriteUInt32(dwCheckPoint);
            writer.WriteUInt32(dwWaitHint);
        }
    }
}