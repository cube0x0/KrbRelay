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
    /// TRANS2_QUERY_PATH_INFORMATION Request
    /// </summary>
    public class Transaction2QueryPathInformationRequest : Transaction2Subcommand
    {
        private const ushort SMB_INFO_PASSTHROUGH = 0x03E8;
        public const int ParametersFixedLength = 6;

        // Parameters:
        public ushort InformationLevel;

        public uint Reserved;
        public string FileName; // SMB_STRING

        // Data:
        public FullExtendedAttributeList GetExtendedAttributeList; // Used with QueryInformationLevel.SMB_INFO_QUERY_EAS_FROM_LIST

        public Transaction2QueryPathInformationRequest() : base()
        {
            GetExtendedAttributeList = new FullExtendedAttributeList();
        }

        public Transaction2QueryPathInformationRequest(byte[] parameters, byte[] data, bool isUnicode) : base()
        {
            InformationLevel = LittleEndianConverter.ToUInt16(parameters, 0);
            Reserved = LittleEndianConverter.ToUInt32(parameters, 4);
            FileName = SMB1Helper.ReadSMBString(parameters, 6, isUnicode);

            if (!IsPassthroughInformationLevel && QueryInformationLevel == QueryInformationLevel.SMB_INFO_QUERY_EAS_FROM_LIST)
            {
                GetExtendedAttributeList = new FullExtendedAttributeList(data, 0);
            }
        }

        public override byte[] GetSetup()
        {
            return LittleEndianConverter.GetBytes((ushort)SubcommandName);
        }

        public override byte[] GetParameters(bool isUnicode)
        {
            int length = ParametersFixedLength;
            if (isUnicode)
            {
                length += FileName.Length * 2 + 2;
            }
            else
            {
                length += FileName.Length + 1;
            }
            byte[] parameters = new byte[length];
            LittleEndianWriter.WriteUInt16(parameters, 0, InformationLevel);
            LittleEndianWriter.WriteUInt32(parameters, 2, Reserved);
            SMB1Helper.WriteSMBString(parameters, 6, isUnicode, FileName);
            return parameters;
        }

        public override byte[] GetData(bool isUnicode)
        {
            if (!IsPassthroughInformationLevel && QueryInformationLevel == QueryInformationLevel.SMB_INFO_QUERY_EAS_FROM_LIST)
            {
                return GetExtendedAttributeList.GetBytes();
            }
            else
            {
                return new byte[0];
            }
        }

        public bool IsPassthroughInformationLevel
        {
            get
            {
                return (InformationLevel >= SMB_INFO_PASSTHROUGH);
            }
        }

        public QueryInformationLevel QueryInformationLevel
        {
            get
            {
                return (QueryInformationLevel)InformationLevel;
            }
            set
            {
                InformationLevel = (ushort)value;
            }
        }

        public FileInformationClass FileInformationClass
        {
            get
            {
                return (FileInformationClass)(InformationLevel - SMB_INFO_PASSTHROUGH);
            }
            set
            {
                InformationLevel = (ushort)((ushort)value + SMB_INFO_PASSTHROUGH);
            }
        }

        public override Transaction2SubcommandName SubcommandName
        {
            get
            {
                return Transaction2SubcommandName.TRANS2_QUERY_PATH_INFORMATION;
            }
        }
    }
}