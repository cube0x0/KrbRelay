using System;

namespace SMBLibrary.SMB1
{
    [Flags]
    public enum PipeState : ushort
    {
        /// <summary>
        /// If set, the named pipe is operating in message mode.
        /// If not set, the named pipe is operating in byte mode.
        /// In message mode, the system treats the bytes read or written in each I/O operation to the pipe as a message unit.
        /// The system MUST perform write operations on message-type pipes as if write-through mode were enabled.
        /// </summary>
        ReadMode = 0x0100,

        /// <summary>
        /// If set, a read or a raw read request returns all data available to be read from the named pipe, up to the maximum read size set in the request.
        /// A write request returns after writing data to the named pipe without waiting for the data to be consumed.
        /// Named pipe non-blocking raw writes are not allowed. Raw writes MUST be performed in blocking mode.
        /// If not set, a read or a raw read request will wait (block) until sufficient data to satisfy the read request becomes available,
        /// or until the request is canceled. A write request blocks until its data is consumed, if the write request length is greater than zero.
        /// </summary>
        Nonblocking = 0x8000,
    }
}