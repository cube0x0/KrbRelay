using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace KrbRelay
{
    internal enum WtsInfoClass
    {
        InitialProgram = 0,
        ApplicationName = 1,
        WorkingDirectory = 2,
        OEMId = 3,
        SessionId = 4,
        UserName = 5,
        WinStationName = 6,
        DomainName = 7,
        ConnectState = 8,
        ClientBuildNumber = 9,
        ClientName = 10,
        ClientDirectory = 11,
        ClientProductId = 12,
        ClientHardwareId = 13,
        ClientAddress = 14,
        ClientDisplay = 15,
        ClientProtocolType = 16
    }

    internal enum WtsConnectStateClass
    {
        Active,
        Connected,
        ConnectQuery,
        Shadow,
        Disconnected,
        Idle,
        Listen,
        Reset,
        Down,
        Init
    }
}
