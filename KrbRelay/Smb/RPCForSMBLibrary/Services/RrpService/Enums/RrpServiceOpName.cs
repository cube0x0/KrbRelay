namespace SMBLibrary.Services
{
    public enum RrpServiceOpName : ushort
    {
        OpenLocalMachine = 2,
        BaseRegCloseKey = 5,
        BaseRegCreateKey = 6,
        BaseRegOpenKey = 15,
        BaseRegQueryInfoKey = 16,
        BaseRegQueryValue = 17,
        BaseRegSaveKey = 20,
    }
}