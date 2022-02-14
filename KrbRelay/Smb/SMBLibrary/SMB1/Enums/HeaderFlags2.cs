using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum HeaderFlags2 : ushort
    {
        LongNamesAllowed = 0x0001, // SMB_FLAGS2_LONG_NAMES
        ExtendedAttributes = 0x0002, // SMB_FLAGS2_EAS
        SecuritySignature = 0x0004, // SMB_FLAGS2_SMB_SECURITY_SIGNATURE
        CompressedData = 0x0008, // SMB_FLAGS2_COMPRESSED
        SecuritySignatureRequired = 0x0010, // SMB_FLAGS2_SMB_SECURITY_SIGNATURE_REQUIRED
        LongNameUsed = 0x0040, // SMB_FLAGS2_IS_LONG_NAME
        ReparsePath = 0x400, // SMB_FLAGS2_REPARSE_PATH

        /// <summary>
        /// Indicates that the client or server supports extended security
        /// </summary>
        ExtendedSecurity = 0x0800, // SMB_FLAGS2_EXTENDED_SECURITY

        DFS = 0x1000, // SMB_FLAGS2_DFS
        ReadIfExecute = 0x2000, // SMB_FLAGS2_PAGING_IO
        NTStatusCode = 0x4000, // SMB_FLAGS2_NT_STATUS
        Unicode = 0x8000, // SMB_FLAGS2_UNICODE
    }
}