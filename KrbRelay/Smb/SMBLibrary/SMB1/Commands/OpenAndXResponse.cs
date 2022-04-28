/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_OPEN_ANDX Response
    /// </summary>
    public class OpenAndXResponse : SMBAndXCommand
    {
        public const int ParametersLength = 30;

        // Parameters:
        // CommandName AndXCommand;
        // byte AndXReserved;
        // ushort AndXOffset;
        public ushort FID;

        public SMBFileAttributes FileAttrs;
        public DateTime? LastWriteTime; // UTime
        public uint FileDataSize;
        public AccessRights AccessRights;
        public ResourceType ResourceType;
        public NamedPipeStatus NMPipeStatus;
        public OpenResults OpenResults;
        public byte[] Reserved; // 6 bytes

        public OpenAndXResponse() : base()
        {
            Reserved = new byte[6];
        }

        public OpenAndXResponse(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            int parametersOffset = 4;
            FID = LittleEndianReader.ReadUInt16(SMBParameters, ref parametersOffset);
            FileAttrs = (SMBFileAttributes)LittleEndianReader.ReadUInt16(SMBParameters, ref parametersOffset);
            LastWriteTime = UTimeHelper.ReadNullableUTime(SMBParameters, ref parametersOffset);
            FileDataSize = LittleEndianReader.ReadUInt32(SMBParameters, ref parametersOffset);
            AccessRights = (AccessRights)LittleEndianReader.ReadUInt16(SMBParameters, ref parametersOffset);
            ResourceType = (ResourceType)LittleEndianReader.ReadUInt16(SMBParameters, ref parametersOffset);
            NMPipeStatus = NamedPipeStatus.Read(SMBParameters, ref parametersOffset);
            OpenResults = OpenResults.Read(SMBParameters, ref parametersOffset);
            Reserved = ByteReader.ReadBytes(SMBParameters, ref parametersOffset, 6);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            SMBParameters = new byte[ParametersLength];
            int parametersOffset = 4;
            LittleEndianWriter.WriteUInt16(SMBParameters, ref parametersOffset, FID);
            LittleEndianWriter.WriteUInt16(SMBParameters, ref parametersOffset, (ushort)FileAttrs);
            UTimeHelper.WriteUTime(SMBParameters, ref parametersOffset, LastWriteTime);
            LittleEndianWriter.WriteUInt32(SMBParameters, ref parametersOffset, FileDataSize);
            LittleEndianWriter.WriteUInt16(SMBParameters, ref parametersOffset, (ushort)AccessRights);
            LittleEndianWriter.WriteUInt16(SMBParameters, ref parametersOffset, (ushort)ResourceType);
            NMPipeStatus.WriteBytes(SMBParameters, ref parametersOffset);
            OpenResults.WriteBytes(SMBParameters, ref parametersOffset);
            ByteWriter.WriteBytes(SMBParameters, ref parametersOffset, Reserved, 6);
            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_OPEN_ANDX;
            }
        }
    }
}