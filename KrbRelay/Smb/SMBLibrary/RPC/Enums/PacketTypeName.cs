namespace SMBLibrary.RPC
{
    // Commented out packet types are connectionless-only
    public enum PacketTypeName : byte
    {
        Request = 0x00,

        // Ping = 0x01,
        Response = 0x02,

        Fault = 0x03,

        //Working = 0x04,
        //NoCall = 0x05,
        //Reject = 0x06,
        //Ack = 0x07,
        //CLCancel = 0x08, // cl_cancel
        //FAck = 0x09,
        //CancelAck = 0x0A, // cancel_ack
        Bind = 0x0B,

        BindAck = 0x0C,
        BindNak = 0x0D, // bind_nak
        AlterContext = 0x0E, // alter_context
        AlterContextResponse = 0x0F, // alter_context_resp
        Shutdown = 0x11,
        COCancel = 0x12, // co_cancel
        Orphaned = 0x13,
    }
}