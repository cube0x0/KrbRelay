using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum Capabilities : uint
    {
        RawMode = 0x00000001, // CAP_RAW_MODE
        MPXMode = 0x00000002, // SMB_COM_READ_MPX
        Unicode = 0x00000004, // CAP_UNICODE
        LargeFiles = 0x00000008, // CAP_LARGE_FILES
        NTSMB = 0x00000010, // CAP_NT_SMBS
        RpcRemoteApi = 0x00000020, // CAP_RPC_REMOTE_APIS
        NTStatusCode = 0x00000040, // CAP_STATUS32
        Level2Oplocks = 0x00000080, // CAP_LEVEL_II_OPLOCKS
        LockAndRead = 0x00000100, // CAP_LOCK_AND_READ
        NTFind = 0x00000200, // CAP_NT_FIND
        DFS = 0x00001000, // CAP_DFS
        InfoLevelPassthrough = 0x00002000, // CAP_INFOLEVEL_PASSTHRU
        LargeRead = 0x00004000, // CAP_LARGE_READX
        LargeWrite = 0x00008000, // CAP_LARGE_WRITEX
        LightWeightIO = 0x00010000, // CAP_LWIO
        Unix = 0x00800000, // CAP_UNIX
        DynamicReauthentication = 0x20000000, // CAP_DYNAMIC_REAUTH

        /// <summary>
        /// The server supports extended security for authentication
        /// </summary>
        ExtendedSecurity = 0x80000000, // CAP_EXTENDED_SECURITY
    }
}