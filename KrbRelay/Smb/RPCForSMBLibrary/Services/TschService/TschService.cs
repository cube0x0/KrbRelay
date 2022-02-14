using System;

namespace SMBLibrary.Services
{
    /// <summary>
    /// [MS-TSCH]
    /// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch
    /// </summary>
    public class TschService : RemoteService
    {
        public const string ServicePipeName = @"atsvc";
        public static readonly Guid ServiceInterfaceGuid = new Guid("86D35949-83C9-4044-B424-DB363231FD0C");
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