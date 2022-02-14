namespace SMBLibrary.Services
{
    public enum RegType : ushort
    {
        REG_BINARY = 3,
        REG_DWORD = 4,
        REG_DWORD_LITTLE_ENDIAN = 4,
        REG_DWORD_BIG_ENDIAN = 5,
        REG_EXPAND_SZ = 2,
        REG_LINK = 6,
        REG_MULTI_SZ = 7,
        REG_NONE = 0,
        REG_QWORD = 11,
        REG_QWORD_LITTLE_ENDIAN = 11,
        REG_SZ = 1,
    }
}