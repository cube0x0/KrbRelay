/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// SMB_COM_OPEN_ANDX Response Extended
    /// </summary>
    public class OpenAndXResponseExtended : SMBAndXCommand
    {
        public const int ParametersLength = 38;

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
        public uint ServerFID;
        public ushort Reserved;
        public AccessMask MaximalAccessRights;
        public AccessMask GuestMaximalAccessRights;

        public OpenAndXResponseExtended() : base()
        {
        }

        public OpenAndXResponseExtended(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            throw new NotImplementedException();
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParametersLength];
            int parametersOffset = 4;
            LittleEndianWriter.WriteUInt16(this.SMBParameters, ref parametersOffset, FID);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, ref parametersOffset, (ushort)FileAttrs);
            UTimeHelper.WriteUTime(this.SMBParameters, ref parametersOffset, LastWriteTime);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref parametersOffset, FileDataSize);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, ref parametersOffset, (ushort)AccessRights);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, ref parametersOffset, (ushort)ResourceType);
            NMPipeStatus.WriteBytes(this.SMBParameters, ref parametersOffset);
            OpenResults.WriteBytes(this.SMBParameters, ref parametersOffset);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref parametersOffset, ServerFID);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, ref parametersOffset, Reserved);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref parametersOffset, (uint)MaximalAccessRights);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref parametersOffset, (uint)GuestMaximalAccessRights);
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