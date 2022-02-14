namespace SMBLibrary.RPC
{
    public enum NegotiationResult : ushort
    {
        Acceptance,
        UserRejection,
        ProviderRejection,

        /// <summary>
        /// Microsoft extension:
        /// [MS-RPCE] 2.2.2.4 - negotiate_ack
        /// </summary>
        NegotiateAck
    }
}