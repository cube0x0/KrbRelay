/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    public enum ReadMode : byte
    {
        ByteMode = 0x00,
        MessageMode = 0x01,
    }

    public enum NamedPipeType : byte
    {
        ByteModePipe = 0x00,
        MessageModePipe = 0x01,
    }

    public enum Endpoint : byte
    {
        ClientSideEnd = 0x00,
        ServerSideEnd = 0x01,
    }

    public enum NonBlocking : byte
    {
        Block = 0x00,
        DoNotBlock = 0x01,
    }

    /// <summary>
    /// SMB_NMPIPE_STATUS
    /// </summary>
    public struct NamedPipeStatus // ushort
    {
        public const int Length = 2;

        public byte ICount;
        public ReadMode ReadMode;
        public NamedPipeType NamedPipeType;
        public Endpoint Endpoint;
        public NonBlocking NonBlocking;

        public NamedPipeStatus(byte[] buffer, int offset)
        {
            ICount = buffer[offset + 0];
            ReadMode = (ReadMode)(buffer[offset + 1] & 0x03);
            NamedPipeType = (NamedPipeType)((buffer[offset + 1] & 0x0C) >> 2);
            Endpoint = (Endpoint)((buffer[offset + 1] & 0x40) >> 6);
            NonBlocking = (NonBlocking)((buffer[offset + 1] & 0x80) >> 7);
        }

        public NamedPipeStatus(ushort value)
        {
            ICount = (byte)(value & 0xFF);
            ReadMode = (ReadMode)((value & 0x0300) >> 8);
            NamedPipeType = (NamedPipeType)((value & 0x0C00) >> 10);
            Endpoint = (Endpoint)((value & 0x4000) >> 14);
            NonBlocking = (NonBlocking)((value & 0x80) >> 15);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            buffer[offset + 0] = ICount;
            buffer[offset + 1] = (byte)((byte)ReadMode & 0x03);
            buffer[offset + 1] |= (byte)(((byte)NamedPipeType << 2) & 0x0C);
            buffer[offset + 1] |= (byte)(((byte)Endpoint << 6) & 0x40);
            buffer[offset + 1] |= (byte)(((byte)NonBlocking << 7) & 0x80);
        }

        public void WriteBytes(byte[] buffer, ref int offset)
        {
            WriteBytes(buffer, offset);
            offset += Length;
        }

        public ushort ToUInt16()
        {
            ushort result = ICount;
            result |= (ushort)(((byte)ReadMode << 8) & 0x0300);
            result |= (ushort)(((byte)NamedPipeType << 10) & 0x0C00);
            result |= (ushort)(((byte)Endpoint << 14) & 0x4000);
            result |= (ushort)(((byte)NonBlocking << 15) & 0x8000);
            return result;
        }

        public static NamedPipeStatus Read(byte[] buffer, ref int offset)
        {
            offset += Length;
            return new NamedPipeStatus(buffer, offset - 2);
        }
    }
}