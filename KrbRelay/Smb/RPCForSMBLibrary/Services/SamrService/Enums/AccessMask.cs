namespace SMBLibrary.Services
{
    public enum AccessMask : uint
    {
        DELETE          = 0x00010000,
        READ_CONTROL    = 0x00020000,
        WRITE_DAC       = 0x00040000,
        WRITE_OWNER     = 0x00080000,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_READ    = 0x80000000,
        GENERIC_WRITE   = 0x40000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_ALL     = 0x10000000
    }
}
