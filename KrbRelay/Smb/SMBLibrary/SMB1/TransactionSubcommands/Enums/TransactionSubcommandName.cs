namespace SMBLibrary.SMB1
{
    public enum TransactionSubcommandName : ushort
    {
        /// <summary>
        /// The 0x0001 subcommand code is interpreted as TRANS_MAILSLOT_WRITE if the operation is being performed on a mailslot.
        /// The same code is interpreted as a TRANS_SET_NMPIPE_STATE (section 2.2.5.1) if the operation is performed on a named pipe.
        /// </summary>
        TRANS_MAILSLOT_WRITE = 0x0001,

        TRANS_SET_NMPIPE_STATE = 0x0001,
        TRANS_RAW_READ_NMPIPE = 0x0011,
        TRANS_QUERY_NMPIPE_STATE = 0x0021,
        TRANS_QUERY_NMPIPE_INFO = 0x0022,
        TRANS_PEEK_NMPIPE = 0x0023,
        TRANS_TRANSACT_NMPIPE = 0x0026,
        TRANS_RAW_WRITE_NMPIPE = 0x0031,
        TRANS_READ_NMPIPE = 0x0036,
        TRANS_WRITE_NMPIPE = 0x0037,
        TRANS_WAIT_NMPIPE = 0x0053,
        TRANS_CALL_NMPIPE = 0x0054,
    }
}