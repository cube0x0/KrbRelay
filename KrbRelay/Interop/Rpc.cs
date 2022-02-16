using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace KrbRelay
{
    public enum AuthnLevel
    {
        Default = 0,
        None = 1,
        Connect = 2,
        Call = 3,
        Pkt = 4,
        PktIntegrity = 5,
        PktPrivacy = 6
    }

    public enum ImpLevel
    {
        Default = 0,
        Anonymous = 1,
        Identify = 2,
        Impersonate = 3,
        Delegate = 4,
    }
}
