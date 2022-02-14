using System;

namespace SMBLibrary.Services
{
    /// <summary>
    /// [MS-SAMR]
    /// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr
    /// </summary>
    public class SamrService : RemoteService
    {
        public const string ServicePipeName = @"samr";
        public static readonly Guid ServiceInterfaceGuid = new Guid("12345778-1234-ABCD-EF00-0123456789AC");
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