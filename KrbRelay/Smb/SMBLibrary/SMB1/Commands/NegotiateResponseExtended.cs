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
    /// SMB_COM_NEGOTIATE Response, NT LAN Manager dialect, Extended Security response
    /// </summary>
    public class NegotiateResponseExtended : SMB1Command
    {
        public const int ParametersLength = 34;

        // Parameters:
        public ushort DialectIndex;

        public SecurityMode SecurityMode;
        public ushort MaxMpxCount;
        public ushort MaxNumberVcs;
        public uint MaxBufferSize;
        public uint MaxRawSize;
        public uint SessionKey;
        public Capabilities Capabilities;
        public DateTime SystemTime;
        public short ServerTimeZone;
        private byte ChallengeLength; // MUST be set to 0

        // Data:
        public Guid ServerGuid;

        public byte[] SecurityBlob;   // [MS-SMB] 3.3.5.2: The server can leave SecurityBlob empty if not configured to send GSS token.

        public NegotiateResponseExtended() : base()
        {
            SecurityBlob = new byte[0];
        }

        public NegotiateResponseExtended(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            DialectIndex = LittleEndianConverter.ToUInt16(SMBParameters, 0);
            SecurityMode = (SecurityMode)ByteReader.ReadByte(SMBParameters, 2);
            MaxMpxCount = LittleEndianConverter.ToUInt16(SMBParameters, 3);
            MaxNumberVcs = LittleEndianConverter.ToUInt16(SMBParameters, 5);
            MaxBufferSize = LittleEndianConverter.ToUInt32(SMBParameters, 7);
            MaxRawSize = LittleEndianConverter.ToUInt32(SMBParameters, 11);
            SessionKey = LittleEndianConverter.ToUInt32(SMBParameters, 15);
            Capabilities = (Capabilities)LittleEndianConverter.ToUInt32(SMBParameters, 19);
            SystemTime = FileTimeHelper.ReadFileTime(SMBParameters, 23);
            ServerTimeZone = LittleEndianConverter.ToInt16(SMBParameters, 31);
            ChallengeLength = ByteReader.ReadByte(SMBParameters, 33);

            ServerGuid = LittleEndianConverter.ToGuid(SMBData, 0);
            SecurityBlob = ByteReader.ReadBytes(SMBData, 16, SMBData.Length - 16);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            ChallengeLength = 0;

            SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(SMBParameters, 0, DialectIndex);
            ByteWriter.WriteByte(SMBParameters, 2, (byte)SecurityMode);
            LittleEndianWriter.WriteUInt16(SMBParameters, 3, MaxMpxCount);
            LittleEndianWriter.WriteUInt16(SMBParameters, 5, MaxNumberVcs);
            LittleEndianWriter.WriteUInt32(SMBParameters, 7, MaxBufferSize);
            LittleEndianWriter.WriteUInt32(SMBParameters, 11, MaxRawSize);
            LittleEndianWriter.WriteUInt32(SMBParameters, 15, SessionKey);
            LittleEndianWriter.WriteUInt32(SMBParameters, 19, (uint)Capabilities);
            FileTimeHelper.WriteFileTime(SMBParameters, 23, SystemTime);
            LittleEndianWriter.WriteInt16(SMBParameters, 31, ServerTimeZone);
            ByteWriter.WriteByte(SMBParameters, 33, ChallengeLength);

            SMBData = new byte[16 + SecurityBlob.Length];
            LittleEndianWriter.WriteGuid(SMBData, 0, ServerGuid);
            ByteWriter.WriteBytes(SMBData, 16, SecurityBlob);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_NEGOTIATE;
            }
        }
    }
}