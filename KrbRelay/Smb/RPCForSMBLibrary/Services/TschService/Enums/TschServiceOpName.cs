namespace SMBLibrary.Services
{
    public enum TschServiceOpName : ushort
    {
        SchRpcRegisterTask = 1,
        SchRpcRun = 12,
        SchRpcDelete = 13,
        SchRpcGetLastRunInfo = 16,
    }
}