using System;

namespace SMBLibrary.Services
{
    /// <summary>
    /// [MS-RRP]
    /// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78
    /// </summary>
    public class RrpService : RemoteService
    {
        public const string ServicePipeName = @"winreg";
        public static readonly Guid ServiceInterfaceGuid = new Guid("338CD001-2244-31F1-AAAA-900038001003");
        public const int ServiceVersion = 1;

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