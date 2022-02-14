namespace SMBLibrary.Services
{
    public enum WorkstationServiceOpName : ushort
    {
        NetrWkstaGetInfo = 0,
        NetrWkstaSetInfo = 1,
        NetrWkstaUserEnum = 2,
        NetrWkstaTransportEnum = 5,
        NetrWkstaTransportAdd = 6,
        NetrWkstaTransportDel = 7,
        NetrUseAdd = 8,
        NetrUseGetInfo = 9,
        NetrUseDel = 10,
        NetrUseEnum = 11,
        NetrWorkstationStatisticsGet = 13,
        NetrGetJoinInformation = 20,
        NetrJoinDomain2 = 22,
        NetrUnjoinDomain2 = 23,
        NetrRenameMachineInDomain2 = 24,
        NetrValidateName2 = 25,
        NetrGetJoinableOUs2 = 26,
        NetrAddAlternateComputerName = 27,
        NetrRemoveAlternateComputerName = 28,
        NetrSetPrimaryComputerName = 29,
        NetrEnumerateComputerNames = 30,
    }
}