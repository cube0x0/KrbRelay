/* Copyright (C) 2017-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;
using System;
using System.Collections.Generic;
using System.IO;

namespace SMBLibrary.Services
{
    public class RPCPipeStream : Stream
    {
        private RemoteService m_service;
        private List<MemoryStream> m_outputStreams; // A stream for each message in order to support message mode named pipe
        private int? m_maxTransmitFragmentSize;

        public RPCPipeStream(RemoteService service)
        {
            m_service = service;
            m_outputStreams = new List<MemoryStream>();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (m_outputStreams.Count > 0)
            {
                int result = m_outputStreams[0].Read(buffer, offset, count);
                if (m_outputStreams[0].Position == m_outputStreams[0].Length)
                {
                    m_outputStreams.RemoveAt(0);
                }
                return result;
            }
            else
            {
                return 0;
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            // [MC-CIFS] In message mode, the system treats the bytes read or written in each I/O operation to the pipe as a message unit.
            RPCPDU rpcRequest = RPCPDU.GetPDU(buffer, offset);
            ProcessRPCRequest(rpcRequest);
        }

        private void ProcessRPCRequest(RPCPDU rpcRequest)
        {
            if (rpcRequest is BindPDU)
            {
                BindAckPDU bindAckPDU = RemoteServiceHelper.GetRPCBindResponse((BindPDU)rpcRequest, m_service);
                m_maxTransmitFragmentSize = bindAckPDU.MaxTransmitFragmentSize;
                Append(bindAckPDU.GetBytes());
            }
            else if (m_maxTransmitFragmentSize.HasValue && rpcRequest is RequestPDU) // if BindPDU was not received, we treat as protocol error
            {
                List<RPCPDU> responsePDUs = RemoteServiceHelper.GetRPCResponse((RequestPDU)rpcRequest, m_service, m_maxTransmitFragmentSize.Value);
                foreach (RPCPDU responsePDU in responsePDUs)
                {
                    Append(responsePDU.GetBytes());
                }
            }
            else
            {
                FaultPDU faultPDU = new FaultPDU();
                faultPDU.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
                faultPDU.DataRepresentation = new DataRepresentationFormat(CharacterFormat.ASCII, ByteOrder.LittleEndian, FloatingPointRepresentation.IEEE);
                faultPDU.CallID = 0;
                faultPDU.AllocationHint = RPCPDU.CommonFieldsLength + FaultPDU.FaultFieldsLength;
                faultPDU.Status = FaultStatus.ProtocolError;
                Append(faultPDU.GetBytes());
            }
        }

        private void Append(byte[] buffer)
        {
            MemoryStream stream = new MemoryStream(buffer);
            m_outputStreams.Add(stream);
        }

        public override void Flush()
        {
        }

        public override void Close()
        {
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override bool CanSeek
        {
            get
            {
                return false;
            }
        }

        public override bool CanRead
        {
            get
            {
                return true;
            }
        }

        public override bool CanWrite
        {
            get
            {
                return true;
            }
        }

        public override long Length
        {
            get
            {
                // Stream.Length only works on Stream implementations where seeking is available.
                throw new NotSupportedException();
            }
        }

        public override long Position
        {
            get
            {
                throw new NotSupportedException();
            }
            set
            {
                throw new NotSupportedException();
            }
        }

        /// <summary>
        /// The length of the first message available in the pipe
        /// </summary>
        public int MessageLength
        {
            get
            {
                if (m_outputStreams.Count > 0)
                {
                    return (int)m_outputStreams[0].Length;
                }
                else
                {
                    return 0;
                }
            }
        }
    }
}