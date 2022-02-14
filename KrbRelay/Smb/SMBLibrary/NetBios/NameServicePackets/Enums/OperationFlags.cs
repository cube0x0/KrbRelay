using System;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.2.1.1. HEADER
    /// </summary>
    [Flags]
    public enum OperationFlags : byte
    {
        Broadcast = 0x01,
        RecursionAvailable = 0x08,
        RecursionDesired = 0x10,
        Truncated = 0x20,
        AuthoritativeAnswer = 0x40,
    }
}