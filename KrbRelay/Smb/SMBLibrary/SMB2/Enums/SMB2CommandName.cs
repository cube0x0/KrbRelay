namespace SMBLibrary.SMB2
{
    public enum SMB2CommandName : ushort
    {
        Negotiate = 0x0000,      // SMB2 NEGOTIATE
        SessionSetup = 0x0001,   // SMB2 SESSION_SETUP
        Logoff = 0x0002,         // SMB2 LOGOFF
        TreeConnect = 0x0003,    // SMB2 TREE_CONNECT
        TreeDisconnect = 0x0004, // SMB2 TREE_DISCONNECT
        Create = 0x0005,         // SMB2 CREATE
        Close = 0x0006,          // SMB2 CLOSE
        Flush = 0x0007,          // SMB2 FLUSH
        Read = 0x0008,           // SMB2 READ
        Write = 0x0009,          // SMB2 WRITE
        Lock = 0x000A,           // SMB2 LOCK
        IOCtl = 0x000B,          // SMB2 IOCTL
        Cancel = 0x000C,         // SMB2 CANCEL
        Echo = 0x000D,           // SMB2 ECHO
        QueryDirectory = 0x000E, // SMB2 QUERY_DIRECTORY
        ChangeNotify = 0x000F,   // SMB2 CHANGE_NOTIFY
        QueryInfo = 0x0010,      // SMB2 QUERY_INFO
        SetInfo = 0x0011,        // SMB2 SET_INFO
        OplockBreak = 0x0012,    // SMB2 OPLOCK_BREAK
    }
}