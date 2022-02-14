namespace SMBLibrary.RPC
{
    public enum FaultStatus : uint
    {
        OpRangeError = 0x1C010002, // nca_op_rng_error
        UnknownInterface = 0x1C010003, // nca_unk_if
        RPCVersionMismatch = 0x1C000008, // nca_rpc_version_mismatch
        ProtocolError = 0x1C01000B, // nca_proto_error
    }
}