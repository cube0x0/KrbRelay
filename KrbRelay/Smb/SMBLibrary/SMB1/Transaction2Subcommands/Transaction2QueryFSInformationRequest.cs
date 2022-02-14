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
    /// TRANS2_QUERY_FS_INFORMATION Request
    /// </summary>
    public class Transaction2QueryFSInformationRequest : Transaction2Subcommand
    {
        private const ushort SMB_INFO_PASSTHROUGH = 0x03E8;
        public const int ParametersLength = 2;

        // Parameters:
        public ushort InformationLevel;

        public Transaction2QueryFSInformationRequest() : base()
        {
        }

        public Transaction2QueryFSInformationRequest(byte[] parameters, byte[] data, bool isUnicode) : base()
        {
            InformationLevel = LittleEndianConverter.ToUInt16(parameters, 0);
        }

        public override byte[] GetSetup()
        {
            return LittleEndianConverter.GetBytes((ushort)SubcommandName);
        }

        public override byte[] GetParameters(bool isUnicode)
        {
            byte[] parameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(parameters, 0, InformationLevel);
            return parameters;
        }

        public bool IsPassthroughInformationLevel
        {
            get
            {
                return (InformationLevel >= SMB_INFO_PASSTHROUGH);
            }
        }

        public QueryFSInformationLevel QueryFSInformationLevel
        {
            get
            {
                return (QueryFSInformationLevel)InformationLevel;
            }
            set
            {
                InformationLevel = (ushort)value;
            }
        }

        public FileSystemInformationClass FileSystemInformationClass
        {
            get
            {
                return (FileSystemInformationClass)(InformationLevel - SMB_INFO_PASSTHROUGH);
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
                return Transaction2SubcommandName.TRANS2_QUERY_FS_INFORMATION;
            }
        }
    }
}