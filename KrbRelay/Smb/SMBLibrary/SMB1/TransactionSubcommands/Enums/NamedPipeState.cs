namespace SMBLibrary.SMB1
{
    public enum NamedPipeState : ushort
    {
        DisconnectedByServer = 0x0001,
        Listening = 0x0002,
        ConnectionToServerOK = 0x0003,
        ServerEndClosed = 0x0004,
    }
}