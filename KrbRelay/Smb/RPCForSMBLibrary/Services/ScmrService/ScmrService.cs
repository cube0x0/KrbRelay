using System;

namespace SMBLibrary.Services
{
    /// <summary>
    /// [MS-SCMR]
    /// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr
    /// </summary>
    public class ScmrService : RemoteService
    {
        public const string ServicePipeName = @"svcctl";
        public static readonly Guid ServiceInterfaceGuid = new Guid("367ABB81-9844-35F1-AD32-98F038001003");
        public const int ServiceVersion = 2;

        public override Guid InterfaceGuid
        {
            get
            {
                return ServiceInterfaceGuid;
            }
        }

        public override string PipeName
        {
            get
            {
                return ServicePipeName;
            }
        }

        public override byte[] GetResponseBytes(ushort opNum, byte[] requestBytes)
        {
            throw new NotImplementedException();
        }
    }
}