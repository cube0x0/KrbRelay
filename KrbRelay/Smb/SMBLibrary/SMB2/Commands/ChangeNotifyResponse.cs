/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 CHANGE_NOTIFY Response
    /// </summary>
    public class ChangeNotifyResponse : SMB2Command
    {
        public const int FixedSize = 8;
        public const int DeclaredSize = 9;

        private ushort StructureSize;
        private ushort OutputBufferOffset;
        private uint OutputBufferLength;
        public byte[] OutputBuffer = new byte[0];

        public ChangeNotifyResponse() : base(SMB2CommandName.ChangeNotify)
        {
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public ChangeNotifyResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            OutputBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 2);
            OutputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            OutputBuffer = ByteReader.ReadBytes(buffer, offset + OutputBufferOffset, (int)OutputBufferLength);
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            OutputBufferOffset = 0;
            OutputBufferLength = (uint)OutputBuffer.Length;
            if (OutputBuffer.Length > 0)
            {
                OutputBufferOffset = SMB2Header.Length + FixedSize;
            }
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, OutputBufferOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, OutputBufferLength);
            ByteWriter.WriteBytes(buffer, offset + FixedSize, OutputBuffer);
        }

        public List<FileNotifyInformation> GetFileNotifyInformation()
        {
            return FileNotifyInformation.ReadList(OutputBuffer, 0);
        }

        public void SetFileNotifyInformation(List<FileNotifyInformation> notifyInformationList)
        {
            OutputBuffer = FileNotifyInformation.GetBytes(notifyInformationList);
        }

        public override int CommandLength
        {
            get
            {
                return FixedSize + OutputBuffer.Length;
            }
        }
    }
}