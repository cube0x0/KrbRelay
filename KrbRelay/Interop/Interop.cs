using System;
using System.Runtime.InteropServices;
using System.Text;

// Contains all the DllImport declarations for native functions used throughout
// the project. Prefer minimal attributes (EntryPoint, CharSet, Convetion, etc.)
// where possible and defined structures as arguments over basic IntPtrs.

namespace KrbRelay
{
    public class Interop
    {
        // LDAP

        [DllImport("wldap32", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint ldap_set_option(IntPtr ld, uint option, ref uint invalue);

        [DllImport("wldap32",CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint ldap_set_option(IntPtr ld, uint option, IntPtr pointer);

        [DllImport("wldap32", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint ldap_connect(IntPtr ld, LDAP_TIMEVAL timeout);

        [DllImport("wldap32", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_init(string hostname, uint port);

        [DllImport(
            "wldap32",
            EntryPoint = "ldap_sasl_bind_s",
            CallingConvention = CallingConvention.Cdecl
        )]
        internal static extern int ldap_sasl_bind(
            [In] IntPtr ld,
            string dn,
            string mechanism,
            IntPtr cred,
            IntPtr serverctrls,
            IntPtr clientctrls,
            out IntPtr msgidp
        );

        [DllImport("wldap32", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ldap_get_option(IntPtr ld, int option, out int value);

        [DllImport(
            "wldap32",
            CharSet = CharSet.Unicode,
            CallingConvention = CallingConvention.Cdecl
        )]
        internal static extern int ldap_search(
            IntPtr ld,
            string @base,
            int scope,
            string filter,
            IntPtr attrs,
            int attrsonly
        );

        [DllImport("wldap32", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ldap_result(
            IntPtr ld,
            int msgid,
            int all,
            LDAP_TIMEVAL timeout,
            ref IntPtr pMessage
        );

        [DllImport("wldap32", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_first_entry(IntPtr ld, IntPtr pMessage);

        [DllImport("wldap32", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_next_entry(IntPtr ld, IntPtr pMessage);

        [DllImport("wldap32", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_get_dn(IntPtr ld, IntPtr message);

        [DllImport("wldap32", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_first_attribute(
            IntPtr ld,
            IntPtr entry,
            ref IntPtr ppBer
        );

        [DllImport("wldap32", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_next_attribute(
            IntPtr ld,
            IntPtr entry,
            ref IntPtr ppBer
        );

        [DllImport("wldap32", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_next_attribute(IntPtr ld, IntPtr entry, IntPtr ppBer);

        [DllImport("wldap32", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_get_values_len(IntPtr ld, IntPtr entry, IntPtr pBer);

        [DllImport(
            "wldap32",
            EntryPoint = "ldap_modify_s",
            CharSet = CharSet.Unicode,
            CallingConvention = CallingConvention.Cdecl
        )]
        internal static extern int ldap_modify(IntPtr ld, string dn, IntPtr mods);

        [DllImport("wldap32", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ldap_unbind(IntPtr ld);

        [DllImport("wldap32", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ldap_value_free_len(IntPtr vals);

        // Session

        [DllImport("Wtsapi32.dll")]
        internal static extern bool WTSQuerySessionInformation(
            IntPtr hServer,
            int sessionId,
            WtsInfoClass wtsInfoClass,
            out System.IntPtr ppBuffer,
            out uint pBytesReturned
        );

        // Encryption

        [DllImport(
            "advapi32.dll",
            EntryPoint = "SystemFunction018",
            SetLastError = true,
            CallingConvention = CallingConvention.StdCall
        )]
        private static extern uint RtlEncryptNtOwfPwdWithNtSesKey(
            [In] byte[] ntOwfPassword,
            [In] ref byte[] sessionkey,
            [In, Out] byte[] encryptedNtOwfPassword
        );

        [DllImport(
            "advapi32.dll",
            EntryPoint = "SystemFunction018",
            SetLastError = true,
            CallingConvention = CallingConvention.StdCall
        )]
        private static extern uint RtlEncryptNtOwfPwdWithNtSesKey(
            [In] byte[] ntOwfPassword,
            [In] byte[] sessionkey,
            [In, Out] byte[] encryptedNtOwfPassword
        );

        internal static uint RtlEncryptNtOwfPwdWithNtSesKey(
            byte[] ntOwfPassword,
            byte[] sessionkey,
            out byte[] encryptedNtOwfPassword
        )
        {
            encryptedNtOwfPassword = new byte[16];
            return RtlEncryptNtOwfPwdWithNtSesKey(
                ntOwfPassword,
                ref sessionkey,
                encryptedNtOwfPassword
            );
        }

        // SSPI

        [DllImport("Secur32.dll")]
        internal unsafe static extern SecurityStatusCode AcceptSecurityContext(
            ref SspiHandle phCredential,
            ref SspiHandle phContext,
            ref SecurityBufferDescriptor pInput,
            AcceptContextReqFlags fContextReq,
            uint TargetDataRep,
            ref SspiHandle phNewContext,
            ref SecurityBufferDescriptor pOutput,
            ref uint pfContextAttr,
            ref LARGE_INTEGER ptsTimeStamp
        );

        [DllImport("secur32.dll")]
        internal unsafe static extern SecurityStatusCode AcquireCredentialsHandle(
            string pszPrincipal,
            string pszPackage, // "Kerberos","NTLM","Negotiative"
            uint fCredentialUse,
            IntPtr pvLogonID,
            IntPtr pAuthData,
            IntPtr pGetKeyFn,
            IntPtr pvGetKeyArgument,
            ref SspiHandle phCredential,
            ref LARGE_INTEGER ptsExpiry
        );

        [DllImport("secur32.dll")]
        internal unsafe static extern SecurityStatusCode InitializeSecurityContext(
            ref SspiHandle phCredential,
            ref SspiHandle phContext,
            string pszTargetName,
            uint fContextReq,
            uint Reserved1,
            uint TargetDataRep,
            ref SecurityBufferDescriptor pInput,
            uint Reserved2,
            ref SspiHandle phNewContext,
            ref SecurityBufferDescriptor pOutput,
            ref uint pfContextAttr,
            ref LARGE_INTEGER ptsExpiry
        );

        [DllImport("secur32.dll")]
        internal unsafe static extern SecurityStatusCode QueryContextAttributes(
            ref SspiHandle phContext,
            uint ulAttribute,
            IntPtr pValue
        );

        [DllImport("Secur32.dll")]
        internal static extern uint DeleteSecurityContext(ref SspiHandle phContext);

        [DllImport("sspicli.dll", EntryPoint = "InitSecurityInterfaceW")]
        internal static extern IntPtr InitSecurityInterface();

        [DllImport("Secur32.dll")]
        internal static extern uint FreeContextBuffer(IntPtr pvContextBuffer);

        [DllImport("Secur32.dll")]
        internal static extern uint FreeCredentialsHandle(ref SspiHandle phCredential);

        // WinAPI

        [DllImport("ntdll.dll")]
        internal static extern UInt32 NtQueryInformationProcess(
            IntPtr processHandle,
            UInt32 processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength,
            ref UInt32 returnLength
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32", SetLastError = true)]
        internal static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [PreserveSig]
        internal static extern uint GetModuleFileName(
            [In] IntPtr hModule,
            [Out] StringBuilder lpFilename,
            [In] [MarshalAs(UnmanagedType.U4)] int nSize
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberOfBytesWritten
        );

        [DllImport("Advapi32.dll")]
        internal static extern int RegOverridePredefKey(IntPtr hKey,IntPtr hNewHKey);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberOfBytesRead
        );

        // RPC
        [DllImport("rpcrt4.dll")]
        internal static extern int RpcServerUseProtseqEp(
            string Protseq,
            uint MaxCalls,
            string Endpoint,
            IntPtr SecurityDescriptor
        );

        [DllImport(
            "Rpcrt4.dll",
            EntryPoint = "RpcServerRegisterAuthInfo",
            CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true
        )]
        internal static extern int RpcServerRegisterAuthInfo(
            String ServerPrincName,
            uint AuthnSvc,
            IntPtr GetKeyFn,
            IntPtr Arg
        );

        // COM

        [DllImport("ole32.dll")]
        internal static extern int CoInitializeSecurity(
            IntPtr pSecDesc,
            int cAuthSvc,
            SOLE_AUTHENTICATION_SERVICE[] asAuthSvc,
            IntPtr pReserved1,
            AuthnLevel dwAuthnLevel,
            ImpLevel dwImpLevel,
            IntPtr pAuthList,
            AuthenticationCapabilities dwCapabilities,
            IntPtr pReserved3
        );

        // Kerberos

        [DllImport("cryptdll.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        internal static extern int CDLocateCSystem(KERB_ETYPE type, out IntPtr pCheckSum);
    }
}
