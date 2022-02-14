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
    /// SMB_COM_SESSION_SETUP_ANDX Request
    /// </summary>
    public class SessionSetupAndXRequest : SMBAndXCommand
    {
        public const int ParametersLength = 26;

        // Parameters:
        public ushort MaxBufferSize;

        public ushort MaxMpxCount;
        public ushort VcNumber;
        public uint SessionKey;
        private ushort OEMPasswordLength;
        private ushort UnicodePasswordLength;
        public uint Reserved;
        public Capabilities Capabilities;

        // Data:
        public byte[] OEMPassword;

        public byte[] UnicodePassword;

        // Padding
        public string AccountName;   // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)

        public string PrimaryDomain; // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
        public string NativeOS;      // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
        public string NativeLanMan;  // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)

        public SessionSetupAndXRequest() : base()
        {
            AccountName = String.Empty;
            PrimaryDomain = String.Empty;
            NativeOS = String.Empty;
            NativeLanMan = String.Empty;
        }

        public SessionSetupAndXRequest(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
            MaxBufferSize = LittleEndianConverter.ToUInt16(this.SMBParameters, 4);
            MaxMpxCount = LittleEndianConverter.ToUInt16(this.SMBParameters, 6);
            VcNumber = LittleEndianConverter.ToUInt16(this.SMBParameters, 8);
            SessionKey = LittleEndianConverter.ToUInt32(this.SMBParameters, 10);
            OEMPasswordLength = LittleEndianConverter.ToUInt16(this.SMBParameters, 14);
            UnicodePasswordLength = LittleEndianConverter.ToUInt16(this.SMBParameters, 16);
            Reserved = LittleEndianConverter.ToUInt32(this.SMBParameters, 18);
            Capabilities = (Capabilities)LittleEndianConverter.ToUInt32(this.SMBParameters, 22);

            OEMPassword = ByteReader.ReadBytes(this.SMBData, 0, OEMPasswordLength);
            UnicodePassword = ByteReader.ReadBytes(this.SMBData, OEMPasswordLength, UnicodePasswordLength);

            int dataOffset = OEMPasswordLength + UnicodePasswordLength;
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                int padding = (1 + OEMPasswordLength + UnicodePasswordLength) % 2;
                dataOffset += padding;
            }
            AccountName = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);
            PrimaryDomain = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);
            NativeOS = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);
            NativeLanMan = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            Capabilities &= ~Capabilities.ExtendedSecurity;

            OEMPasswordLength = (ushort)OEMPassword.Length;
            UnicodePasswordLength = (ushort)UnicodePassword.Length;

            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 4, MaxBufferSize);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 6, MaxMpxCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 8, VcNumber);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, 10, SessionKey);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 14, OEMPasswordLength);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 16, UnicodePasswordLength);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, 18, Reserved);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, 22, (uint)Capabilities);

            int padding = 0;
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                padding = (1 + OEMPasswordLength + UnicodePasswordLength) % 2;
                this.SMBData = new byte[OEMPassword.Length + UnicodePassword.Length + padding + (AccountName.Length + 1) * 2 + (PrimaryDomain.Length + 1) * 2 + (NativeOS.Length + 1) * 2 + (NativeLanMan.Length + 1) * 2];
            }
            else
            {
                this.SMBData = new byte[OEMPassword.Length + UnicodePassword.Length + AccountName.Length + 1 + PrimaryDomain.Length + 1 + NativeOS.Length + 1 + NativeLanMan.Length + 1];
            }
            int offset = 0;
            ByteWriter.WriteBytes(this.SMBData, ref offset, OEMPassword);
            ByteWriter.WriteBytes(this.SMBData, ref offset, UnicodePassword);
            offset += padding;
            SMB1Helper.WriteSMBString(this.SMBData, ref offset, isUnicode, AccountName);
            SMB1Helper.WriteSMBString(this.SMBData, ref offset, isUnicode, PrimaryDomain);
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