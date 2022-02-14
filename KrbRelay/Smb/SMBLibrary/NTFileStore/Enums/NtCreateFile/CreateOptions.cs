using System;

namespace SMBLibrary
{
    [Flags]
    public enum CreateOptions : uint
    {
        /// <summary>
        /// The file being created or opened is a directory file.
        /// With this option, the CreateDisposition field MUST be set to FILE_CREATE, FILE_OPEN, or FILE_OPEN_IF.
        /// </summary>
        FILE_DIRECTORY_FILE = 0x00000001,

        /// <summary>
        /// Applications that write data to the file MUST actually transfer the data into the file before any write request is considered complete.
        /// If FILE_NO_INTERMEDIATE_BUFFERING is set, the server MUST perform as if FILE_WRITE_THROUGH is set in the create request.
        /// </summary>
        FILE_WRITE_THROUGH = 0x00000002,

        /// <summary>
        /// This option indicates that access to the file can be sequential.
        /// The server can use this information to influence its caching and read-ahead strategy for this file.
        /// The file MAY in fact be accessed randomly, but the server can optimize its caching and read-ahead policy for sequential access.
        /// </summary>
        FILE_SEQUENTIAL_ONLY = 0x00000004,

        /// <summary>
        /// The file SHOULD NOT be cached or buffered in an internal buffer by the server.
        /// This option is incompatible when the FILE_APPEND_DATA bit field is set in the DesiredAccess field.
        /// </summary>
        FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008,

        FILE_SYNCHRONOUS_IO_ALERT = 0x00000010,

        FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020,

        /// <summary>
        /// If the file being opened is a directory, the server MUST fail the request with STATUS_FILE_IS_A_DIRECTORY
        /// </summary>
        FILE_NON_DIRECTORY_FILE = 0x00000040,

        FILE_CREATE_TREE_CONNECTION = 0x00000080,

        FILE_COMPLETE_IF_OPLOCKED = 0x00000100,

        /// <summary>
        /// The application that initiated the client's request does not support extended attributes (EAs).
        /// If the EAs on an existing file being opened indicate that the caller SHOULD support EAs to correctly interpret the file, the server SHOULD fail this request with STATUS_ACCESS_DENIED.
        /// </summary>
        FILE_NO_EA_KNOWLEDGE = 0x00000200,

        /// <summary>
        /// formerly known as FILE_OPEN_FOR_RECOVERY
        /// </summary>
        FILE_OPEN_REMOTE_INSTANCE = 0x00000400,

        /// <summary>
        /// Indicates that access to the file can be random.
        /// The server MAY use this information to influence its caching and read-ahead strategy for this file.
        /// This is a hint to the server that sequential read-ahead operations might not be appropriate on the file.
        /// </summary>
        FILE_RANDOM_ACCESS = 0x00000800,

        /// <summary>
        /// The file SHOULD be automatically deleted when the last open request on this file is closed.
        /// When this option is set, the DesiredAccess field MUST include the DELETE flag.
        /// This option is often used for temporary files.
        /// </summary>
        FILE_DELETE_ON_CLOSE = 0x00001000,

        /// <summary>
        /// Opens a file based on the FileId.
        /// If this option is set, the server MUST fail the request with STATUS_NOT_SUPPORTED in the Status field of the SMB Header in the server response.
        /// </summary>
        FILE_OPEN_BY_FILE_ID = 0x00002000,

        /// <summary>
        /// The file is being opened or created for the purposes of either a backup or a restore operation.
        /// Thus, the server can make appropriate checks to ensure that the caller is capable of overriding
        /// whatever security checks have been placed on the file to allow a backup or restore operation to occur.
        /// The server can check for certain access rights to the file before checking the DesiredAccess field.
        /// </summary>
        FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000,

        /// <summary>
        /// When a new file is created, the file MUST NOT be compressed, even if it is on a compressed volume.
        /// The flag MUST be ignored when opening an existing file.
        /// </summary>
        FILE_NO_COMPRESSION = 0x00008000,

        FILE_OPEN_REQUIRING_OPLOCK = 0x00010000,

        FILE_DISALLOW_EXCLUSIVE = 0x00020000,

        FILE_RESERVE_OPFILTER = 0x00100000,

        FILE_OPEN_REPARSE_POINT = 0x00200000,

        /// <summary>
        /// In a hierarchical storage management environment, this option requests that the file SHOULD NOT be recalled from tertiary storage such as tape.
        /// A file recall can take up to several minutes in a hierarchical storage management environment.
        /// The clients can specify this option to avoid such delays.
        /// </summary>
        FILE_OPEN_NO_RECALL = 0x00400000,

        FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000,
    }
}