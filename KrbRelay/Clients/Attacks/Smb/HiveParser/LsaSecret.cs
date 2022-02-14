using System;
using System.Linq;

namespace KrbRelay.HiveParser
{
    internal class LsaSecret
    {
        public LsaSecret(byte[] inputData)
        {
            version = inputData.Take(4).ToArray();
            enc_key_id = inputData.Skip(4).Take(16).ToArray();
            enc_algo = inputData.Skip(20).Take(4).ToArray();
            flags = inputData.Skip(24).Take(4).ToArray();
            data = inputData.Skip(28).ToArray();
        }

        public byte[] version { get; set; }
        public byte[] enc_key_id { get; set; }
        public byte[] enc_algo { get; set; }
        public byte[] flags { get; set; }
        public byte[] data { get; set; }
    }

    internal class LsaSecretBlob
    {
        public LsaSecretBlob(byte[] inputData)
        {
            length = BitConverter.ToInt16(inputData.Take(4).ToArray(), 0);
            unk = inputData.Skip(4).Take(12).ToArray();
            secret = inputData.Skip(16).Take(length).ToArray();
        }

        public int length { get; set; }
        public byte[] unk { get; set; }
        public byte[] secret { get; set; }
    }
}