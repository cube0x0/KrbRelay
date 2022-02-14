using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum SecurityMode : byte
    {
        /// <summary>
        /// If clear, the server supports only Share Level access control.
        /// If set, the server supports only User Level access control.
        /// </summary>
        UserSecurityMode = 0x01, // NEGOTIATE_USER_SECURITY

        /// <summary>
        /// If clear, the server supports only plaintext password authentication.
        /// If set, the server supports challenge/response authentication.
        /// Note: Windows 2000 and above do not support plain-text passwords by default.
        /// </summary>
        EncryptPasswords = 0x02, // NEGOTIATE_ENCRYPT_PASSWORDS

        SecuritySignaturesEnabled = 0x04, // NEGOTIATE_SECURITY_SIGNATURES_ENABLED
        SecuritySignaturesRequired = 0x08, // NEGOTIATE_SECURITY_SIGNATURES_REQUIRED
    }
}