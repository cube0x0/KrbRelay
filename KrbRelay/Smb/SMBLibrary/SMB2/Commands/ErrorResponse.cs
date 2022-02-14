/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 ERROR Response
    /// </summary>
    public class ErrorResponse : SMB2Command
    {
        public const int FixedSize = 8;
        public const int DeclaredSize = 9;

        private ushort StructureSize;
        public byte ErrorContextCount;
        public byte Reserved;
        private uint ByteCount;
        public byte[] ErrorData = new byte[0];

        public ErrorResponse(SMB2CommandName commandName) : base(commandName)
        {
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public ErrorResponse(SMB2CommandName commandName, NTStatus status) : base(commandName)
        {
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
            Header.Status = status;
        }

        public ErrorResponse(SMB2CommandName commandName, NTStatus status, byte[] errorData) : base(commandName)
        {
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
            Header.Status = status;
            ErrorData = errorData;
        }

        public ErrorResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            ErrorContextCount = ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 2);
            Reserved = ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 3);
            ByteCount = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            ErrorData = ByteReader.ReadBytes(buffer, offset + SMB2Header.Length + 8, (int)ByteCount);
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            ByteCount = (uint)ErrorData.Length;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            ByteWriter.WriteByte(buffer, offset + 2, ErrorContextCount);
            ByteWriter.WriteByte(buffer, offset + 3, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, ByteCount);
            if (ErrorData.Length > 0)
            {
                ByteWriter.WriteBytes(buffer, offset + 8, ErrorData);
            }
            else
            {
                // If the ByteCount field is zero then the server MUST supply an ErrorData field that is one byte in length, and SHOULD set that byte to zero
                ByteWriter.WriteBytes(buffer, offset + 8, new byte[1]);
            }
        }

        public override int CommandLength
        {
            get
            {
                // If the ByteCount field is zero then the server MUST supply an ErrorData field that is one byte in length
                return FixedSize + Math.Max(ErrorData.Length, 1);
            }
        }
    }
}