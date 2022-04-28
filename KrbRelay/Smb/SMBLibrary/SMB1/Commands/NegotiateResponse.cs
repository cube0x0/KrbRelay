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
    /// SMB_COM_NEGOTIATE Response, NT LAN Manager dialect
    /// </summary>
    public class NegotiateResponse : SMB1Command
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
        private byte ChallengeLength;

        // Data:
        public byte[] Challenge;

        public string DomainName; // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)
        public string ServerName; // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)

        public NegotiateResponse() : base()
        {
            Challenge = new byte[0];
            DomainName = String.Empty;
            ServerName = String.Empty;
        }

        public NegotiateResponse(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
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

            int dataOffset = 0;
            Challenge = ByteReader.ReadBytes(SMBData, ref dataOffset, ChallengeLength);
            // [MS-CIFS] <90> Padding is not added before DomainName
            // DomainName and ServerName are always in Unicode
            DomainName = SMB1Helper.ReadSMBString(SMBData, ref dataOffset, true);
            ServerName = SMB1Helper.ReadSMBString(SMBData, ref dataOffset, true);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            ChallengeLength = (byte)Challenge.Length;

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

            // [MS-CIFS] <90> Padding is not added before DomainName
            // DomainName and ServerName are always in Unicode
            SMBData = new byte[Challenge.Length + (DomainName.Length + 1) * 2 + (ServerName.Length + 1) * 2];
            int offset = 0;
            ByteWriter.WriteBytes(SMBData, ref offset, Challenge);
            SMB1Helper.WriteSMBString(SMBData, ref offset, true, DomainName);
            SMB1Helper.WriteSMBString(SMBData, ref offset, true, ServerName);

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