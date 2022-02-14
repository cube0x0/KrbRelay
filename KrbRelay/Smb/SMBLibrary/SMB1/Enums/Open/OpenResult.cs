namespace SMBLibrary.SMB1
{
    public enum OpenResult : byte
    {
        Reserved = 0x00,
        FileExistedAndWasOpened = 0x01,
        NotExistedAndWasCreated = 0x02,
        FileExistedAndWasTruncated = 0x03,
    }
}