/* Copyright (C) 2014-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.RPC
{
    // See DCE 1.1: Remote Procedure Call, Chapter 14.1 - Data Representation Format Label
    public enum CharacterFormat : byte
    {
        ASCII = 0x00,
        EBCDIC = 0x01,
    }

    public enum ByteOrder : byte
    {
        BigEndian = 0x00,
        LittleEndian = 0x01,
    }

    public enum FloatingPointRepresentation : byte
    {
        IEEE = 0x00,
        VAX = 0x01,
        Cray = 0x02,
        IBM = 0x03,
    }

    public struct DataRepresentationFormat // uint
    {
        public CharacterFormat CharacterFormat;
        public ByteOrder ByteOrder;
        public FloatingPointRepresentation FloatingPointRepresentation;

        public DataRepresentationFormat(CharacterFormat characterFormat, ByteOrder byteOrder, FloatingPointRepresentation floatingPointRepresentation)
        {
            CharacterFormat = characterFormat;
            ByteOrder = byteOrder;
            FloatingPointRepresentation = floatingPointRepresentation;
        }

        public DataRepresentationFormat(byte[] buffer, int offset)
        {
            CharacterFormat = (CharacterFormat)(buffer[offset + 0] & 0x0F);
            ByteOrder = (ByteOrder)(buffer[offset + 0] >> 4);
            FloatingPointRepresentation = (FloatingPointRepresentation)(buffer[offset + 1]);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            buffer[offset + 0] = (byte)CharacterFormat;
            buffer[offset + 0] |= (byte)((byte)ByteOrder << 4);
            buffer[offset + 1] = (byte)FloatingPointRepresentation;
        }
    }
}