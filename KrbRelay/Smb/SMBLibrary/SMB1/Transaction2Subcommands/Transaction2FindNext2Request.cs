/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS2_FIND_NEXT2 Request
    /// </summary>
    public class Transaction2FindNext2Request : Transaction2Subcommand
    {
        // Parameters:
        public ushort SID; // Search handle

        public ushort SearchCount;
        public FindInformationLevel InformationLevel;
        public uint ResumeKey;
        public FindFlags Flags;
        public string FileName; // SMB_STRING

        // Data:
        public ExtendedAttributeNameList GetExtendedAttributeList; // Used with FindInformationLevel.SMB_INFO_QUERY_EAS_FROM_LIST

        public Transaction2FindNext2Request() : base()
        {
            GetExtendedAttributeList = new ExtendedAttributeNameList();
        }

        public Transaction2FindNext2Request(byte[] parameters, byte[] data, bool isUnicode) : base()
        {
            SID = LittleEndianConverter.ToUInt16(parameters, 0);
            SearchCount = LittleEndianConverter.ToUInt16(parameters, 2);
            InformationLevel = (FindInformationLevel)LittleEndianConverter.ToUInt16(parameters, 4);
            ResumeKey = LittleEndianConverter.ToUInt32(parameters, 6);
            Flags = (FindFlags)LittleEndianConverter.ToUInt16(parameters, 10);
            FileName = SMB1Helper.ReadSMBString(parameters, 12, isUnicode);

            if (InformationLevel == FindInformationLevel.SMB_INFO_QUERY_EAS_FROM_LIST)
            {
                GetExtendedAttributeList = new ExtendedAttributeNameList(data, 0);
            }
        }

        public override byte[] GetSetup()
        {
            return LittleEndianConverter.GetBytes((ushort)SubcommandName);
        }

        public override byte[] GetParameters(bool isUnicode)
        {
            int length = 12;
            if (isUnicode)
            {
                length += FileName.Length * 2 + 2;
            }
            else
            {
                length += FileName.Length + 1;
            }

            byte[] parameters = new byte[length];
            LittleEndianWriter.WriteUInt16(parameters, 0, SID);
            LittleEndianWriter.WriteUInt16(parameters, 2, SearchCount);
            LittleEndianWriter.WriteUInt16(parameters, 4, (ushort)InformationLevel);
            LittleEndianWriter.WriteUInt32(parameters, 6, ResumeKey);
            LittleEndianWriter.WriteUInt16(parameters, 10, (ushort)Flags);
            SMB1Helper.WriteSMBString(parameters, 12, isUnicode, FileName);

            return parameters;
        }

        public override byte[] GetData(bool isUnicode)
        {
            if (InformationLevel == FindInformationLevel.SMB_INFO_QUERY_EAS_FROM_LIST)
            {
                return GetExtendedAttributeList.GetBytes();
            }
            else
            {
                return new byte[0];
            }
        }

        public override Transaction2SubcommandName SubcommandName
        {
            get
            {
                return Transaction2SubcommandName.TRANS2_FIND_NEXT2;
            }
        }
    }
}