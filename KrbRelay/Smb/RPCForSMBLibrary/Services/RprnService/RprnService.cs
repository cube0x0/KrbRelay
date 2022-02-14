using System;

namespace SMBLibrary.Services
{
    /// <summary>
    /// [MS-RPRN]
    /// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn
    /// </summary>
    public class RprnService : RemoteService
    {
        public const string ServicePipeName = @"spoolss";
        public static readonly Guid ServiceInterfaceGuid = new Guid("12345678-1234-ABCD-EF00-0123456789AB");
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