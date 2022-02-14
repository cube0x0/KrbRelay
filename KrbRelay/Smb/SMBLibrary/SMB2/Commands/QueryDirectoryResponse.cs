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
    /// SMB2 QUERY_DIRECTORY Response
    /// </summary>
    public class QueryDirectoryResponse : SMB2Command
    {
        public const int FixedLength = 8;
        public const int DeclaredSize = 9;

        private ushort StructureSize;
        private ushort OutputBufferOffset;
        private uint OutputBufferLength;
        public byte[] OutputBuffer = new byte[0];

        public QueryDirectoryResponse() : base(SMB2CommandName.QueryDirectory)
        {
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public QueryDirectoryResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            OutputBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 2);
            OutputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            OutputBuffer = ByteReader.ReadBytes(buffer, offset + (int)OutputBufferOffset, (int)OutputBufferLength);
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            OutputBufferOffset = 0;
            OutputBufferLength = (uint)OutputBuffer.Length;
            if (OutputBuffer.Length > 0)
            {
                OutputBufferOffset = SMB2Header.Length + FixedLength;
            }
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, OutputBufferOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, OutputBufferLength);
            ByteWriter.WriteBytes(buffer, offset + FixedLength, OutputBuffer);
        }

        public List<QueryDirectoryFileInformation> GetFileInformationList(FileInformationClass fileInformationClass)
        {
            if (OutputBuffer.Length > 0)
            {
                return QueryDirectoryFileInformation.ReadFileInformationList(OutputBuffer, 0, fileInformationClass);
            }
            else
            {
                return new List<QueryDirectoryFileInformation>();
            }
        }

        public void SetFileInformationList(List<QueryDirectoryFileInformation> fileInformationList)
        {
            OutputBuffer = QueryDirectoryFileInformation.GetBytes(fileInformationList);
        }

        public override int CommandLength
        {
            get
            {
                return FixedLength + OutputBuffer.Length;
            }
        }
    }
}