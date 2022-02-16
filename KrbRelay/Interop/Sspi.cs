using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace KrbRelay
{
    [Flags]
    internal enum SecurityBufferType : uint
    {
        Version = 0,
        Empty = 0,
        Data = 1,
        Token = 2,
        PkgParams = 3,
        Missing = 4,
        Extra = 5,
        StreamTrailer = 6,
        StreamHeader = 7,
        Padding = 9,
        Stream = 10,
        Mechlist = 11,
        MechlistSignature = 12,
        Target = 13,
        ChannelBindings = 14,
        ChangePassResponse = 15,
        TargetHost = 16,
        Alert = 17,
        ApplicationProtocols = 18,
        SrtpProtectionProfiles = 19,
        SrtpMasterKeyIdentifier = 20,
        TokenBinding = 21,
        PresharedKey = 22,
        PresharedKeyIdentity = 23,
        DtlsMtu = 24,
        AttrMask = 0xF0000000,
        Readonly = 0x80000000,
        ReadonlyWithChecksum = 0x10000000
    }

    [Flags]
    internal enum SecurityDataRep : uint
    {
        Native = 0x00000010,
        Network = 0x00000000
    }

    internal enum SecurityStatusCode : uint
    {
        Success = 0,
        ContinueNeeded = 0x00090312,
        CompleteNeeded = 0x00090313,
        CompleteAndContinue = 0x00090314,
        AsyncCallPending = 0x00090368,
        ContextExpired = 0x00090317,
        ContinueNeededMessageOk = 0x00090366,
        GenericExtensionReceived = 0x00090316,
        IncompleteCredentials = 0x00090320,
        LocalLogon = 0x00090315,
        MessageFragment = 0x00090364,
        NoLsaContext = 0x00090323,
        NoRenegotiation = 0x00090360,
        Renegotiate = 0x00090321,
        SignatureNeeded = 0x0009035C,
        AlgorithmMismatch = 0x80090331,
        ApplicationProtocolMismatch = 0x80090367,
        BadBindings = 0x80090346,
        BadPkgid = 0x80090316,
        BufferTooSmall = 0x80090321,
        CannotInstall = 0x80090307,
        CannotPack = 0x80090309,
        CertExpired = 0x80090328,
        CertUnknown = 0x80090327,
        CertWrongUsage = 0x80090349,
        CrossrealmDelegationFailure = 0x80090357,
        CryptoSystemInvalid = 0x80090337,
        DecryptFailure = 0x80090330,
        DelegationPolicy = 0x8009035E,
        DelegationRequired = 0x80090345,
        DowngradeDetected = 0x80090350,
        EncryptFailure = 0x80090329,
        ExtBufferTooSmall = 0x8009036A,
        IllegalMessage = 0x80090326,
        IncompleteMessage = 0x80090318,
        InsufficientBuffers = 0x8009036B,
        InsufficientMemory = 0x80090300,
        InternalError = 0x80090304,
        InvalidHandle = 0x80090301,
        InvalidParameter = 0x8009035D,
        InvalidToken = 0x80090308,
        InvalidUpnName = 0x80090369,
        IssuingCaUntrusted = 0x80090352,
        IssuingCaUntrustedKdc = 0x80090359,
        KdcCertExpired = 0x8009035A,
        KdcCertRevoked = 0x8009035B,
        KdcInvalidRequest = 0x80090340,
        KdcUnableToRefer = 0x80090341,
        KdcUnknownEtype = 0x80090342,
        LogonDenied = 0x8009030C,
        MaxReferralsExceeded = 0x80090338,
        MessageAltered = 0x8009030F,
        MultipleAccounts = 0x80090347,
        MustBeKdc = 0x80090339,
        MutualAuthFailed = 0x80090363,
        NotOwner = 0x80090306,
        NoAuthenticatingAuthority = 0x80090311,
        NoContext = 0x80090361,
        NoCredentials = 0x8009030E,
        NoImpersonation = 0x8009030B,
        NoIpAddresses = 0x80090335,
        NoKerbKey = 0x80090348,
        NoPaData = 0x8009033C,
        NoS4uProtSupport = 0x80090356,
        NoTgtReply = 0x80090334,
        OnlyHttpsAllowed = 0x80090365,
        OutOfSequence = 0x80090310,
        PkinitClientFailure = 0x80090354,
        PkinitNameMismatch = 0x8009033D,
        Pku2uCertFailure = 0x80090362,
        PolicyNltmOnly = 0x8009035F,
        QopNotSupported = 0x8009030A,
        RevocationOfflineC = 0x80090353,
        RevocationOfflineKdc = 0x80090358,
        SecpkgNotFound = 0x80090305,
        SecurityQosFailed = 0x80090332,
        ShutdownInProgress = 0x8009033F,
        SmartcardCertExpired = 0x80090355,
        SmartcardCertRevoked = 0x80090351,
        SmartcardLogonRequired = 0x8009033E,
        StrongCryptoNotSupported = 0x8009033A,
        TargetUnknown = 0x80090303,
        TimeSkew = 0x80090324,
        TooManyPrincipals = 0x8009033B,
        UnfinishedContextDeleted = 0x80090333,
        UnknownCredentials = 0x8009030D,
        UnsupportedFunction = 0x80090302,
        UnsupportedPreauth = 0x80090343,
        UntrustedRoot = 0x80090325,
        WrongCredentialHandle = 0x80090336,
        WrongPrincipal = 0x80090322
    }

    [Flags]
    internal enum AcceptContextRetFlags
    {
        None = 0,
        Delegate = 0x00000001,
        MutualAuth = 0x00000002,
        ReplayDetect = 0x00000004,
        SequenceDetect = 0x00000008,
        Confidentiality = 0x00000010,
        UseSessionKey = 0x00000020,
        SessionTicket = 0x00000040,
        AllocatedMemory = 0x00000100,
        UsedDceStyle = 0x00000200,
        Datagram = 0x00000400,
        Connection = 0x00000800,
        CallLevel = 0x00002000,
        ThirdLegFailed = 0x00004000,
        ExtendedError = 0x00008000,
        Stream = 0x00010000,
        Integrity = 0x00020000,
        Licensing = 0x00040000,
        Identify = 0x00080000,
        NullSession = 0x00100000,
        AllowNonUserLogons = 0x00200000,
        AllowContextReplay = 0x00400000,
        FragmentOnly = 0x00800000,
        NoToken = 0x01000000,
        NoAdditionalToken = 0x02000000
    }

    [Flags]
    internal enum AcceptContextReqFlags
    {
        None = 0,
        Delegate = 0x00000001,
        MutualAuth = 0x00000002,
        ReplayDetect = 0x00000004,
        SequenceDetect = 0x00000008,
        Confidentiality = 0x00000010,
        UseSessionKey = 0x00000020,
        SessionTicket = 0x00000040,
        AllocateMemory = 0x00000100,
        UseDceStyle = 0x00000200,
        Datagram = 0x00000400,
        Connection = 0x00000800,
        CallLevel = 0x00001000,
        FragmentSupplied = 0x00002000,
        ExtendedError = 0x00008000,
        Stream = 0x00010000,
        Integrity = 0x00020000,
        Licensing = 0x00040000,
        Identify = 0x00080000,
        AllowNullSessions = 0x00100000,
        AllowNonUserLogons = 0x00200000,
        AllowContextReplay = 0x00400000,
        FragmentToFit = 0x00800000,
        NoToken = 0x01000000,
        ProxyBindings = 0x04000000,
        AllowMissingBindings = 0x10000000
    }

    internal unsafe delegate SecurityStatusCode AcceptSecurityContextFunc(
        SspiHandle* phCredential,
        SspiHandle* phContext, // This might be null on first call, ref hates that
        SecurityBufferDescriptor* pInput,
        AcceptContextReqFlags fContextReq,
        uint TargetDataRep,
        SspiHandle* phNewContext,
        SecurityBufferDescriptor* pOutput,
        uint* pfContextAttr,
        LARGE_INTEGER* ptsTimeStamp
    );

    internal unsafe delegate SecurityStatusCode AcquireCredentialsHandleFunc(
        string pszPrincipal,
        string pszPackage, // "Kerberos","NTLM","Negotiative"
        uint fCredentialUse,
        IntPtr pvLogonID,
        IntPtr pAuthData,
        IntPtr pGetKeyFn,
        IntPtr pvGetKeyArgument,
        SspiHandle* phCredential,
        LARGE_INTEGER* ptsExpiry
    );

    internal unsafe delegate SecurityStatusCode InitializeSecurityContextFunc(
        SspiHandle* phCredential,
        SspiHandle* phContext,
        string pszTargetName,
        uint fContextReq,
        uint Reserved1,
        uint TargetDataRep,
        SecurityBufferDescriptor* pInput,
        uint Reserved2,
        SspiHandle* phNewContext,
        SecurityBufferDescriptor* pOutput,
        uint* pfContextAttr,
        LARGE_INTEGER* ptsExpiry
    );

    internal unsafe delegate SecurityStatusCode QueryContextAttributesFunc(
        SspiHandle* phContext,
        uint ulAttribute,
        IntPtr pValue
    );


    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    internal struct SecurityFunctionTable
    {
        public uint dwVersion;
        public IntPtr EnumerateSecurityPackages;
        public IntPtr QueryCredentialsAttributes;
        public IntPtr AcquireCredentialsHandle;
        public IntPtr FreeCredentialHandle;
        public IntPtr Reserved1;
        public IntPtr InitializeSecurityContext;
        public IntPtr AcceptSecurityContext;
        public IntPtr CompleteAuthToken;
        public IntPtr DeleteSecurityContext;
        public IntPtr ApplyControlToken;
        public IntPtr QueryContextAttributes;
        public IntPtr ImpersonateSecurityContext;
        public IntPtr RevertSecurityContext;
        public IntPtr MakeSignature;
        public IntPtr VerifySignature;
        public IntPtr FreeContextBuffer;
        public IntPtr QuerySecurityPackageInfo;
        public IntPtr Reserved2;
        public IntPtr Reserved3;
        public IntPtr ExportSecurityContext;
        public IntPtr ImportSecurityContext;
        public IntPtr AddCredentials;
        public IntPtr Reserved4;
        public IntPtr QuerySecurityContextToken;
        public IntPtr EncryptMessage;
        public IntPtr DecryptMessage;
        public IntPtr SetContextAttributes;
        public IntPtr SetCredentialsAttributes;
        public IntPtr ChangeAccountPassword;
        public IntPtr Reserved5;
        public IntPtr QueryContextAttributesEx;
        public IntPtr QueryCredentialsAttributesEx;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SspiHandle
    {
        public IntPtr High;
        public IntPtr Low;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityBufferDescriptor : IDisposable
    {
        public SecurityBufferType Version;
        public int NumBuffers;
        public IntPtr BufferPtr;

        public SecurityBufferDescriptor(int bufferSize)
        {
            Version = SecurityBufferType.Version;
            NumBuffers = 1;
            var buffer = new SecurityBuffer(bufferSize);
            BufferPtr = Marshal.AllocHGlobal(Marshal.SizeOf(buffer));
            Marshal.StructureToPtr(buffer, BufferPtr, false);
        }

        public SecurityBufferDescriptor(byte[] secBufferBytes)
        {
            Version = SecurityBufferType.Version;
            NumBuffers = 1;
            var buffer = new SecurityBuffer(secBufferBytes);
            BufferPtr = Marshal.AllocHGlobal(Marshal.SizeOf(buffer));
            Marshal.StructureToPtr(buffer, BufferPtr, false);
        }

        public SecurityBufferDescriptor(SecurityBuffer[] buffers)
        {
            if (buffers == null || buffers.Length == 0)
            {
                throw new ArgumentException("cannot be null or 0 length", "buffers");
            }

            Version = SecurityBufferType.Version;
            NumBuffers = buffers.Length;
            BufferPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecurityBuffer)) * NumBuffers);

            for (int i = 0; i < buffers.Length; i++)
            {
                Marshal.StructureToPtr(
                    buffers[i],
                    BufferPtr + i * Marshal.SizeOf(typeof(SecurityBuffer)),
                    false
                );
            }
        }

        public List<SecurityBuffer> GetBuffers()
        {
            if (BufferPtr == IntPtr.Zero)
            {
                throw new InvalidOperationException("BufferPtr is NULL");
            }

            List<SecurityBuffer> buffers = new List<SecurityBuffer>();
            for (int index = 0; index < NumBuffers; index++)
            {
                buffers.Add(
                    (SecurityBuffer)Marshal.PtrToStructure(
                        BufferPtr + (index * Marshal.SizeOf(typeof(SecurityBuffer))),
                        typeof(SecurityBuffer)
                    )
                );
            }

            return buffers;
        }

        public byte[] ToByteArray()
        {
            var bytes = new List<byte>();
            foreach (var buffer in GetBuffers())
            {
                for (int i = 0; i < buffer.Count; i++)
                {
                    bytes.Add(Marshal.ReadByte(buffer.Token + i));
                }
            }

            return bytes.ToArray();
        }

        public SecurityBuffer GetTokenBuffer()
        {
            return GetBuffers().Where(b => (b.BufferType & SecurityBufferType.Token) != 0).First();
        }

        public byte[] GetTokenBytes()
        {
            return GetTokenBuffer().ToByteArray();
        }

        public SecurityBuffer UpdateTokenBytes(byte[] bytes)
        {
            SecurityBuffer tokenBuffer = GetTokenBuffer();
            tokenBuffer.Replace(bytes);
            return tokenBuffer;
        }

        public void Dispose()
        {
            if (BufferPtr != IntPtr.Zero)
            {
                foreach (var buffer in GetBuffers())
                {
                    buffer.Dispose();
                }

                Marshal.FreeHGlobal(BufferPtr);
                BufferPtr = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityBuffer : IDisposable
    {
        public int Count;
        public SecurityBufferType BufferType;
        public IntPtr Token;

        public SecurityBuffer(int bufferSize)
        {
            Count = bufferSize;
            BufferType = SecurityBufferType.Token;
            Token = Marshal.AllocHGlobal(bufferSize);
        }

        public SecurityBuffer(byte[] bytes)
        {
            Count = bytes.Length;
            BufferType = SecurityBufferType.Token;
            Token = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, Token, bytes.Length);
        }

        public SecurityBuffer(byte[] bytes, SecurityBufferType bufferType)
        {
            BufferType = bufferType;

            if (bytes != null && bytes.Length != 0)
            {
                Count = bytes.Length;
                Token = Marshal.AllocHGlobal(Count);
                Marshal.Copy(bytes, 0, Token, Count);
            }
            else
            {
                Count = 0;
                Token = IntPtr.Zero;
            }
        }

        public byte[] ToByteArray()
        {
            var bytes = new List<byte>();
            for (int i = 0; i < Count; i++)
            {
                bytes.Add(Marshal.ReadByte(Token + i));
            }

            return bytes.ToArray();
        }

        public void Replace(byte[] newBytes)
        {
            if (newBytes.Length > Count)
            {
                throw new InvalidOperationException("Allocated buffer is too small");
            };
            Count = newBytes.Length;
            Marshal.Copy(newBytes, 0, Token, Count);
        }

        public void Dispose()
        {
            if (Token != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Token);
                Token = IntPtr.Zero;
            }
        }
    }
}
