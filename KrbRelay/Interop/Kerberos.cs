using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace KrbRelay
{
    // https://tools.ietf.org/html/rfc3961
    internal enum KERB_ETYPE : UInt32
    {
        des_cbc_crc = 1,
        des_cbc_md4 = 2,
        des_cbc_md5 = 3,
        des3_cbc_md5 = 5,
        des3_cbc_sha1 = 7,
        dsaWithSHA1_CmsOID = 9,
        md5WithRSAEncryption_CmsOID = 10,
        sha1WithRSAEncryption_CmsOID = 11,
        rc2CBC_EnvOID = 12,
        rsaEncryption_EnvOID = 13,
        rsaES_OAEP_ENV_OID = 14,
        des_ede3_cbc_Env_OID = 15,
        des3_cbc_sha1_kd = 16,
        aes128_cts_hmac_sha1 = 17,
        aes256_cts_hmac_sha1 = 18,
        rc4_hmac = 23,
        rc4_hmac_exp = 24,
        subkey_keymaterial = 65
    }

    // From Vincent LE TOUX' "MakeMeEnterpriseAdmin"
    //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L1773-L1794
    [StructLayout(LayoutKind.Sequential)]
    internal struct KERB_ECRYPT
    {
        private int Type0;
        public int BlockSize;
        private int Type1;
        public int KeySize;
        public int Size;
        private int unk2;
        private int unk3;
        public IntPtr AlgName;
        public IntPtr Initialize;
        public IntPtr Encrypt;
        public IntPtr Decrypt;
        public IntPtr Finish;
        public IntPtr HashPassword;
        private IntPtr RandomKey;
        private IntPtr Control;
        private IntPtr unk0_null;
        private IntPtr unk1_null;
        private IntPtr unk2_null;
    };

    internal delegate int KERB_ECRYPT_HashPassword(
        UNICODE_STRING Password,
        UNICODE_STRING Salt,
        int count,
        byte[] output
    );
}
