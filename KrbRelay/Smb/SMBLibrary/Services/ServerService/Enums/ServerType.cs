using System;

namespace SMBLibrary.Services
{
    /// <summary>
    /// [MS-SRVS] 2.2.2.7 Software Type Flags
    /// </summary>
    [Flags]
    public enum ServerType : uint
    {
        Workstation = 0x00000001, // SV_TYPE_WORKSTATION
        Server = 0x00000002, // SV_TYPE_SERVER
        SqlServer = 0x00000004, // SV_TYPE_SQLSERVER
        DomainController = 0x00000008, // SV_TYPE_DOMAIN_CTRL
        BackupDomainController = 0x00000010, // SV_TYPE_DOMAIN_BAKCTRL
        NetworkTimeSource = 0x00000020, // SV_TYPE_TIME_SOURCE
        AppleFileProtocolServer = 0x00000040, // SV_TYPE_AFP
        NovellServer = 0x00000080, // SV_TYPE_NOVELL
        DomainMember = 0x00000100, // SV_TYPE_DOMAIN_MEMBER
        PrintQueueServer = 0x00000200, // SV_TYPE_PRINTQ_SERVER
        DialInServer = 0x00000400, // SV_TYPE_DIALIN_SERVER
        XenixServer = 0x00000800, // SV_TYPE_XENIX_SERVER
        WindowsNT = 0x00001000, // SV_TYPE_NT
        WindowsForWorkgroupServer = 0x00002000, // SV_TYPE_WFW
        FileAndPrintForNetware = 0x00004000, // SV_TYPE_SERVER_MFPN
        ServerNT = 0x00008000, // SV_TYPE_SERVER_NT
        PotentialBrowser = 0x00010000, // SV_TYPE_POTENTIAL_BROWSER
        BackupBrowser = 0x00020000,// SV_TYPE_BACKUP_BROWSER
        MasterBrowser = 0x00040000,// SV_TYPE_MASTER_BROWSER
        DomainMaster = 0x00080000,// SV_TYPE_DOMAIN_MASTER
        Windows = 0x00400000, // SV_TYPE_WINDOWS
        DfsServer = 0x00800000, // Not in the official documents
        TerminalServer = 0x02000000, // SV_TYPE_TERMINALSERVER
        ClusterVirtualServer = 0x04000000, // SV_TYPE_CLUSTER_NT
        NTCluster = 0x10000000, // SV_TYPE_CLUSTER_NT
        LocalListOnly = 0x40000000, // SV_TYPE_LOCAL_LIST_ONLY
        PrimaryDomain = 0x80000000,// SV_TYPE_DOMAIN_ENUM

        All = 0xFFFFFFFF, // SV_TYPE_ALL
    }
}