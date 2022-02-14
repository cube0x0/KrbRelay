using System;

namespace SMBLibrary.Authentication.NTLM
{
    [Flags]
    public enum NegotiateFlags : uint
    {
        UnicodeEncoding = 0x00000001,         // NTLMSSP_NEGOTIATE_UNICODE
        OEMEncoding = 0x00000002,             // NTLM_NEGOTIATE_OEM
        TargetNameSupplied = 0x00000004,      // NTLMSSP_REQUEST_TARGET
        Sign = 0x00000010,                    // NTLMSSP_NEGOTIATE_SIGN
        Seal = 0x00000020,                    // NTLMSSP_NEGOTIATE_SEAL
        Datagram = 0x00000040,                // NTLMSSP_NEGOTIATE_DATAGRAM

        /// <summary>
        /// LanManagerSessionKey and ExtendedSessionSecurity are mutually exclusive
        /// If both are set then LanManagerSessionKey must be ignored
        /// </summary>
        LanManagerSessionKey = 0x00000080,    // NTLMSSP_NEGOTIATE_LM_KEY

        NTLMSessionSecurity = 0x00000200,     // NTLMSSP_NEGOTIATE_NTLM

        /// <summary>
        /// If set, the connection SHOULD be anonymous
        /// </summary>
        Anonymous = 0x00000800,

        DomainNameSupplied = 0x00001000,      // NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
        WorkstationNameSupplied = 0x00002000, // NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
        AlwaysSign = 0x00008000,              // NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        TargetTypeDomain = 0x00010000,        // NTLMSSP_TARGET_TYPE_DOMAIN
        TargetTypeServer = 0x00020000,        // NTLMSSP_TARGET_TYPE_SERVER

        /// <summary>
        /// LanManagerSessionKey and ExtendedSessionSecurity are mutually exclusive
        /// If both are set then LanManagerSessionKey must be ignored.
        /// NTLM v2 requires this flag to be set.
        /// </summary>
        ExtendedSessionSecurity = 0x00080000, // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY

        Identify = 0x00100000,                // NTLMSSP_NEGOTIATE_IDENTIFY
        RequestLMSessionKey = 0x00400000,     // NTLMSSP_REQUEST_NON_NT_SESSION_KEY
        TargetInfo = 0x00800000,              // NTLMSSP_NEGOTIATE_TARGET_INFO
        Version = 0x02000000,                 // NTLMSSP_NEGOTIATE_VERSION
        Use128BitEncryption = 0x20000000,     // NTLMSSP_NEGOTIATE_128
        KeyExchange = 0x40000000,             // NTLMSSP_NEGOTIATE_KEY_EXCH
        Use56BitEncryption = 0x80000000,      // NTLMSSP_NEGOTIATE_56
    }
}