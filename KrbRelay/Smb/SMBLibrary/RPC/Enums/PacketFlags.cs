using System;

namespace SMBLibrary.RPC
{
    [Flags]
    public enum PacketFlags : byte
    {
        FirstFragment = 0x01, // PFC_FIRST_FRAG
        LastFragment = 0x02, // PFC_LAST_FRAG
        PendingCancel = 0x04, // PFC_PENDING_CANCEL
        ConcurrntMultiplexing = 0x10, // PFC_CONC_MPX
        DidNotExecute = 0x20, // PFC_DID_NOT_EXECUTE
        Maybe = 0x40, // PFC_MAYBE
        ObjectUUID = 0x80, // PFC_OBJECT_UUID
    }
}