/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 SESSION_SETUP Response
    /// </summary>
    public class SessionSetupResponse : SMB2Command
    {
        public const int FixedSize = 8;
        public const int DeclaredSize = 9;

        private ushort StructureSize;
        public SessionFlags SessionFlags;
        private ushort SecurityBufferOffset;
        private ushort SecurityBufferLength;
        public byte[] SecurityBuffer = new byte[0];

        public SessionSetupResponse() : base(SMB2CommandName.SessionSetup)
        {
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public SessionSetupResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            SessionFlags = (SessionFlags)LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 2);
            SecurityBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 4);
            SecurityBufferLength = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 6);
            SecurityBuffer = ByteReader.ReadBytes(buffer, offset + SecurityBufferOffset, SecurityBufferLength);
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            SecurityBufferOffset = 0;
            SecurityBufferLength = (ushort)SecurityBuffer.Length;
            if (SecurityBuffer.Length > 0)
            {
                SecurityBufferOffset = SMB2Header.Length + FixedSize;
            }
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, (ushort)SessionFlags);
            LittleEndianWriter.WriteUInt16(buffer, offset + 4, SecurityBufferOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 6, SecurityBufferLength);
            ByteWriter.WriteBytes(buffer, offset + 8, SecurityBuffer);
        }

        public override int CommandLength
        {
            get
            {
                return FixedSize + SecurityBuffer.Length;
            }
        }
    }
}