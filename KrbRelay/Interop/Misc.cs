using System;
using System.Runtime.InteropServices;

// All enums, structs, and helper types not specifically fitting into another file

namespace KrbRelay
{
    internal enum AuthenticationCapabilities
    {
        None = 0,
        MutualAuth = 0x1,
        StaticCloaking = 0x20,
        DynamicCloaking = 0x40,
        AnyAuthority = 0x80,
        MakeFullsic = 0x100,
        Default = 0x800,
        SecureRefs = 0x2,
        AccessControl = 0x4,
        Appid = 0x8,
        Dynamic = 0x10,
        RequireFullsic = 0x200,
        AutoImpersonate = 0x400,
        NoCustomMarshal = 0x2000,
        DisableAaa = 0x1000
    }

    internal struct SOLE_AUTHENTICATION_SERVICE
    {
        public int dwAuthnSvc;
        public int dwAuthzSvc;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string pPrincipalName;
        public int hr;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr buffer;

        public UNICODE_STRING(string s)
        {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.StringToHGlobalUni(s);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(buffer);
        }
    }

    internal struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public UIntPtr UniqueProcessId;
        public int InheritedFromUniqueProcessId;

        public int Size
        {
            get { return (int)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)); }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LARGE_INTEGER
    {
        public uint LowPart;
        public int HighPart;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_INTEGER
    {
        public uint LowPart;
        public int HighPart;
    };
}
