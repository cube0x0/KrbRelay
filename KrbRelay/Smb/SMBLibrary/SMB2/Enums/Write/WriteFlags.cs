namespace SMBLibrary.SMB2
{
    public enum WriteFlags : uint
    {
        WriteThrough = 0x00000001, // SMB2_WRITEFLAG_WRITE_THROUGH
        Unbuffered = 0x00000002,   // SMB2_WRITEFLAG_WRITE_UNBUFFERED
    }
}