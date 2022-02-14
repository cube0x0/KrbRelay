namespace SMBLibrary.RPC
{
    public enum RejectionReason : ushort
    {
        NotSpecified,
        AbstractSyntaxNotSupported,
        ProposedTransferSyntaxesNotSupported,
        LocalLimitExceeded,
    }
}