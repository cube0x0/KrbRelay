using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum TreeConnectFlags : ushort
    {
        /// <summary>
        /// If set and SMB_Header.TID is valid, the tree connect specified by the TID in the SMB
        /// header of the request SHOULD be disconnected when the server sends the response. If this tree disconnect fails, then the error SHOULD be ignored
        /// If set and TID is invalid, the server MUST ignore this bit.
        /// </summary>
        DisconnectTID = 0x0001, // TREE_CONNECT_ANDX_DISCONNECT_TID

        /// <summary>
        /// SMB 1.0 addition.
        /// If set, then the client is requesting signing key protection.
        /// </summary>
        ExtendedSignatures = 0x0004, // TREE_CONNECT_ANDX_EXTENDED_SIGNATURES

        /// <summary>
        /// SMB 1.0 addition.
        /// If set, then the client is requesting extended information in the SMB_COM_TREE_CONNECT_ANDX response.
        /// </summary>
        ExtendedResponse = 0x0008, // TREE_CONNECT_ANDX_EXTENDED_RESPONSE
    }
}