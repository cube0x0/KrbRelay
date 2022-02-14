/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS2_CREATE_DIRECTORY Request
    /// </summary>
    public class Transaction2CreateDirectoryRequest : Transaction2Subcommand
    {
        // Parameters
        public uint Reserved;

        public string DirectoryName; // SMB_STRING

        // Data
        public FullExtendedAttributeList ExtendedAttributeList;

        public Transaction2CreateDirectoryRequest() : base()
        { }

        public Transaction2CreateDirectoryRequest(byte[] parameters, byte[] data, bool isUnicode) : base()
        {
            Reserved = LittleEndianConverter.ToUInt32(parameters, 0);
            DirectoryName = SMB1Helper.ReadSMBString(parameters, 4, isUnicode);
            ExtendedAttributeList = new FullExtendedAttributeList(data);
        }

        public override byte[] GetSetup()
        {
            return LittleEndianConverter.GetBytes((ushort)SubcommandName);
        }

        public override byte[] GetParameters(bool isUnicode)
        {
            int length = 4;
            length += isUnicode ? DirectoryName.Length * 2 + 2 : DirectoryName.Length + 1 + 1;
            byte[] parameters = new byte[length];
            LittleEndianWriter.WriteUInt32(parameters, 0, Reserved);
            SMB1Helper.WriteSMBString(parameters, 4, isUnicode, DirectoryName);
            return parameters;
        }

        public override byte[] GetData(bool isUnicode)
        {
            return ExtendedAttributeList.GetBytes();
        }

        public override Transaction2SubcommandName SubcommandName
        {
            get
            {
                return Transaction2SubcommandName.TRANS2_CREATE_DIRECTORY;
            }
        }
    }
}