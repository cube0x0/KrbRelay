namespace SMBLibrary.SMB2
{
    public enum SMB2Dialect : ushort
    {
        SMB202 = 0x0202, // SMB 2.0.2
        SMB210 = 0x0210, // SMB 2.1
        SMB300 = 0x0300, // SMB 3.0
        SMB302 = 0x0302, // SMB 3.0.2
        SMB311 = 0x0311, // SMB 3.1.1

        /// <summary>
        /// indicates that the server implements SMB 2.1 or future dialect revisions and expects
        /// the client to send a subsequent SMB2 Negotiate request to negotiate the actual SMB 2
        /// Protocol revision to be used.
        /// The wildcard revision number is sent only in response to a multi-protocol negotiate
        /// request with the "SMB 2.???" dialect string.
        /// </summary>
        SMB2xx = 0x02FF, // SMB 2.xx
    }
}