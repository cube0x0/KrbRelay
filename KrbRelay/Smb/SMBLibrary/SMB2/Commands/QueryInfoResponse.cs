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
    /// SMB2 QUERY_INFO Response
    /// </summary>
    public class QueryInfoResponse : SMB2Command
    {
        public const int FixedSize = 8;
        public const int DeclaredSize = 9;

        private ushort StructureSize;
        private ushort OutputBufferOffset;
        private uint OutputBufferLength;
        public byte[] OutputBuffer = new byte[0];

        public QueryInfoResponse() : base(SMB2CommandName.QueryInfo)
        {
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public QueryInfoResponse(byte[] buffer, int offset) : base(buffer, offset)
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

        public FileInformation GetFileInformation(FileInformationClass informationClass)
        {
            return FileInformation.GetFileInformation(OutputBuffer, 0, informationClass);
        }

        public FileSystemInformation GetFileSystemInformation(FileSystemInformationClass informationClass)
        {
            return FileSystemInformation.GetFileSystemInformation(OutputBuffer, 0, informationClass);
        }

        public SecurityDescriptor GetSecurityInformation()
        {
            return new SecurityDescriptor(OutputBuffer, 0);
        }

        public void SetFileInformation(FileInformation fileInformation)
        {
            OutputBuffer = fileInformation.GetBytes();
        }

        public void SetFileSystemInformation(FileSystemInformation fileSystemInformation)
        {
            OutputBuffer = fileSystemInformation.GetBytes();
        }

        public void SetSecurityInformation(SecurityDescriptor securityDescriptor)
        {
            OutputBuffer = securityDescriptor.GetBytes();
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