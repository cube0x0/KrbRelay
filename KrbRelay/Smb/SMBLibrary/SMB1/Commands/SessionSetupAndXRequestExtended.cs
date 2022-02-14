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
    /// SMB_COM_SESSION_SETUP_ANDX Extended Request
    /// </summary>
    public class SessionSetupAndXRequestExtended : SMBAndXCommand
    {
        public const int ParametersLength = 24;

        // Parameters:
        public ushort MaxBufferSize;

        public ushort MaxMpxCount;
        public ushort VcNumber;
        public uint SessionKey;
        private ushort SecurityBlobLength;
        public uint Reserved;
        public Capabilities Capabilities;

        // Data:
        public byte[] SecurityBlob;

        public string NativeOS;     // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)
        public string NativeLanMan; // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)

        public SessionSetupAndXRequestExtended() : base()
        {
            NativeOS = String.Empty;
            NativeLanMan = String.Empty;
        }

        public SessionSetupAndXRequestExtended(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
            MaxBufferSize = LittleEndianConverter.ToUInt16(this.SMBParameters, 4);
            MaxMpxCount = LittleEndianConverter.ToUInt16(this.SMBParameters, 6);
            VcNumber = LittleEndianConverter.ToUInt16(this.SMBParameters, 8);
            SessionKey = LittleEndianConverter.ToUInt32(this.SMBParameters, 10);
            SecurityBlobLength = LittleEndianConverter.ToUInt16(this.SMBParameters, 14);
            Reserved = LittleEndianConverter.ToUInt32(this.SMBParameters, 16);
            Capabilities = (Capabilities)LittleEndianConverter.ToUInt32(this.SMBParameters, 20);

            SecurityBlob = ByteReader.ReadBytes(this.SMBData, 0, SecurityBlobLength);

            int dataOffset = SecurityBlob.Length;
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                int padding = (1 + SecurityBlobLength) % 2;
                dataOffset += padding;
            }
            NativeOS = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);
            NativeLanMan = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            Capabilities |= Capabilities.ExtendedSecurity;
            SecurityBlobLength = (ushort)SecurityBlob.Length;

            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 4, MaxBufferSize);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 6, MaxMpxCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 8, VcNumber);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, 10, SessionKey);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 14, SecurityBlobLength);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, 16, Reserved);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, 20, (uint)Capabilities);

            int padding = 0;
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                padding = (1 + SecurityBlobLength) % 2;
                this.SMBData = new byte[SecurityBlob.Length + padding + (NativeOS.Length + 1) * 2 + (NativeLanMan.Length + 1) * 2];
            }
            else
            {
                this.SMBData = new byte[SecurityBlob.Length + NativeOS.Length + 1 + NativeLanMan.Length + 1];
            }
            int offset = 0;
            ByteWriter.WriteBytes(this.SMBData, ref offset, SecurityBlob);
            offset += padding;
            SMB1Helper.WriteSMBString(this.SMBData, ref offset, isUnicode, NativeOS);
            SMB1Helper.WriteSMBString(this.SMBData, ref offset, isUnicode, NativeLanMan);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_SESSION_SETUP_ANDX;
            }
        }
    }
}