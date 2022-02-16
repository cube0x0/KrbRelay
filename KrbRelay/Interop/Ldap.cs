using System;
using System.Runtime.InteropServices;
using System.Text;
using SMBLibrary;

namespace KrbRelay
{
    internal enum LdapModOperation
    {
        Add = 0x00,
        Delete = 0x01,
        Replace = 0x02,
        BValues = 0x80
    }

    internal enum LdapSearchScope
    {
        Base = 0x0000,
        BaseObject = Base,
        One = 0x0001,
        OneLevel = One,
        Sub = 0x0002,
        SubTree = Sub,
        Subordinate = 0x0003, /* OpenLDAP extension */
        Children = Subordinate,
        Default = -1, /* OpenLDAP extension */
    }

    internal enum LdapResultType
    {
        Error = -1,
        Timeout = 0,
        Bind = 0x61,
        SearchEntry = 0x64,
        SearchReference = 0x73,
        SearchResult = 0x65,
        Modify = 0x67,
        Add = 0x69,
        Delete = 0x6b,
        Moddn = 0x6d,
        Compare = 0x6f,
        Extended = 0x78,
        Intermediate = 0x79
    }

    internal enum LdapStatus
    {
        Success = 0,
        OperationsError = 1,
        ProtocolError = 2,
        TimelimitExceeded = 3,
        SizelimitExceeded = 4,
        CompareFalse = 5,
        CompareTrue = 6,
        AuthMethodNotSupported = 7,
        StrongAuthRequired = 8,
        Referral = 9,
        AdminLimitExceeded = 11,
        UnavailableCriticalExtension = 12,
        ConfidentialityRequired = 13,
        SaslBindInProgress = 14,
        NoSuchAttribute = 16,
        UndefinedType = 17,
        InappropriateMatching = 18,
        ConstraintViolation = 19,
        TypeOrValueExists = 20,
        InvalidSyntax = 21,
        NoSuchObject = 32,
        AliasProblem = 33,
        InvalidDnSyntax = 34,
        IsLeaf = 35,
        AliasDerefProblem = 36,
        InappropriateAuth = 48,
        InvalidCredentials = 49,
        InsufficientAccess = 50,
        Busy = 51,
        Unavailable = 52,
        UnwillingToPerform = 53,
        LoopDetect = 54,
        NamingViolation = 64,
        ObjectClassViolation = 65,
        NotAllowedOnNonleaf = 66,
        NotAllowedOnRdn = 67,
        AlreadyExists = 68,
        NoObjectClassMods = 69,
        ResultsTooLarge = 70,
        AffectsMultipleDsas = 71,
        Other = 80,
        ServerDown = -1,
        LocalError = -2,
        EncodingError = -3,
        DecodingError = -4,
        Timeout = -5,
        AuthUnknown = -6,
        FilterError = -7,
        UserCancelled = -8,
        ParamError = -9,
        NoMemory = -10,
        ConnectError = -11,
        NotSupported = -12,
        ControlNotFound = -13,
        NoResultsReturned = -14,
        MoreResultsToReturn = -15,
        ClientLoop = -16,
        ReferralLimitExceeded = -17,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal class berval
    {
        public int bv_len;
        public IntPtr bv_val = IntPtr.Zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    public sealed class LDAP_TIMEVAL
    {
        public int tv_sec;
        public int tv_usec;
    }

    //https://github.com/go-win/go-windows/blob/3c4cf4813fb68a44704529efb5f5c78ecbb1b380/windows/win32/ldap/enums.go#L11

    [StructLayout(LayoutKind.Sequential)]
    internal class LDAPMod
    {
        /// <summary>
        /// Values that you want to add, delete, or replace.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct mod_vals
        {
            /// <summary>
            /// Pointer to a NULL terminated array of string values for the attribute.
            /// </summary>
            [FieldOffset(0)]
            public IntPtr modv_strvals;

            /// <summary>
            /// Pointer to a NULL-terminated array of berval structures for the attribute.
            /// </summary>
            [FieldOffset(0)]
            public IntPtr modv_bvals;
        }

        /// <summary>
        /// The operation to be performed on the attribute and the type of data specified as the attribute values.
        /// </summary>
        public int mod_op;

        /// <summary>
        /// Pointer to the attribute type that you want to add, delete, or replace.
        /// </summary>
        public IntPtr mod_type;

        /// <summary>
        /// A NULL-terminated array of string values for the attribute.
        /// </summary>
        public mod_vals mod_vals_u;
        public IntPtr mod_next;
    }
}
