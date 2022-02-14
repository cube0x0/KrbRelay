/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;
using Utilities;

namespace SMBLibrary.NetBios
{
    public class NBTConnectionReceiveBuffer
    {
        private byte[] m_buffer;
        private int m_readOffset = 0;
        private int m_bytesInBuffer = 0;
        private int? m_packetLength;

        public NBTConnectionReceiveBuffer() : this(SessionPacket.MaxSessionPacketLength)
        {
        }

        /// <param name="bufferLength">Must be large enough to hold the largest possible NBT packet</param>
        public NBTConnectionReceiveBuffer(int bufferLength)
        {
            if (bufferLength < SessionPacket.MaxSessionPacketLength)
            {
                throw new ArgumentException("bufferLength must be large enough to hold the largest possible NBT packet");
            }
            m_buffer = new byte[bufferLength];
        }

        public void IncreaseBufferSize(int bufferLength)
        {
            byte[] buffer = new byte[bufferLength];
            if (m_bytesInBuffer > 0)
            {
                Array.Copy(m_buffer, m_readOffset, buffer, 0, m_bytesInBuffer);
                m_readOffset = 0;
            }
            m_buffer = buffer;
        }

        public void SetNumberOfBytesReceived(int numberOfBytesReceived)
        {
            m_bytesInBuffer += numberOfBytesReceived;
        }

        public bool HasCompletePacket()
        {
            if (m_bytesInBuffer >= 4)
            {
                if (!m_packetLength.HasValue)
                {
                    m_packetLength = SessionPacket.GetSessionPacketLength(m_buffer, m_readOffset);
                }
                return m_bytesInBuffer >= m_packetLength.Value;
            }
            return false;
        }

        /// <summary>
        /// HasCompletePacket must be called and return true before calling DequeuePacket
        /// </summary>
        /// <exception cref="System.IO.InvalidDataException"></exception>
        public SessionPacket DequeuePacket()
        {
            SessionPacket packet;
            try
            {
                packet = SessionPacket.GetSessionPacket(m_buffer, m_readOffset);
            }
            catch (IndexOutOfRangeException ex)
            {
                throw new InvalidDataException("Invalid NetBIOS session packet", ex);
            }
            RemovePacketBytes();
            return packet;
        }

        /// <summary>
        /// HasCompletePDU must be called and return true before calling DequeuePDUBytes
        /// </summary>
        public byte[] DequeuePacketBytes()
        {
            byte[] packetBytes = ByteReader.ReadBytes(m_buffer, m_readOffset, m_packetLength.Value);
            RemovePacketBytes();
            return packetBytes;
        }

        private void RemovePacketBytes()
        {
            m_bytesInBuffer -= m_packetLength.Value;
            if (m_bytesInBuffer == 0)
            {
                m_readOffset = 0;
                m_packetLength = null;
            }
            else
            {
                m_readOffset += m_packetLength.Value;
                m_packetLength = null;
                if (!HasCompletePacket())
                {
                    Array.Copy(m_buffer, m_readOffset, m_buffer, 0, m_bytesInBuffer);
                    m_readOffset = 0;
                }
            }
        }

        public byte[] Buffer
        {
            get
            {
                return m_buffer;
            }
        }

        public int WriteOffset
        {
            get
            {
                return m_readOffset + m_bytesInBuffer;
            }
        }

        public int BytesInBuffer
        {
            get
            {
                return m_bytesInBuffer;
            }
        }

        public int AvailableLength
        {
            get
            {
                return m_buffer.Length - (m_readOffset + m_bytesInBuffer);
            }
        }
    }
}