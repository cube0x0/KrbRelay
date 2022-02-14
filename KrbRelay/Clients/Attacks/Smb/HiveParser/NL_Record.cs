using System;
using System.Linq;

namespace KrbRelay.HiveParser
{
    internal class NL_Record
    {
        public NL_Record(byte[] inputData)
        {
            userLength = BitConverter.ToInt16(inputData.Take(2).ToArray(), 0);
            domainNameLength = BitConverter.ToInt16(inputData.Skip(2).Take(2).ToArray(), 0);
            dnsDomainLength = BitConverter.ToInt16(inputData.Skip(60).Take(2).ToArray(), 0);
            IV = inputData.Skip(64).Take(16).ToArray();
            encryptedData = inputData.Skip(96).Take(inputData.Length - 96).ToArray();
        }

        public int userLength { get; set; }
        public int domainNameLength { get; set; }
        public int dnsDomainLength { get; set; }
        public byte[] IV { get; set; }
        public byte[] encryptedData { get; set; }
    }
}