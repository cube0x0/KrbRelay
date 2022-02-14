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
    /// TRANS2_QUERY_FILE_INFORMATION Response
    /// </summary>
    public class Transaction2QueryFileInformationResponse : Transaction2Subcommand
    {
        public const int ParametersLength = 2;

        // Parameters:
        public ushort EaErrorOffset; // Meaningful only when request's InformationLevel is SMB_INFO_QUERY_EAS_FROM_LIST

        // Data:
        public byte[] InformationBytes = new byte[0];

        public Transaction2QueryFileInformationResponse() : base()
        {
        }

        public Transaction2QueryFileInformationResponse(byte[] parameters, byte[] data, bool isUnicode) : base()
        {
            EaErrorOffset = LittleEndianConverter.ToUInt16(parameters, 0);
            InformationBytes = data;
        }

        public override byte[] GetParameters(bool isUnicode)
        {
            return LittleEndianConverter.GetBytes(EaErrorOffset);
        }

        public override byte[] GetData(bool isUnicode)
        {
            return InformationBytes;
        }

        public QueryInformation GetQueryInformation(QueryInformationLevel queryInformationLevel)
        {
            return QueryInformation.GetQueryInformation(InformationBytes, queryInformationLevel);
        }

        public void SetQueryInformation(QueryInformation queryInformation)
        {
            InformationBytes = queryInformation.GetBytes();
        }

        /// <remarks>
        /// Support for pass-through Information Levels must be enabled.
        /// </remarks>
        public FileInformation GetFileInformation(FileInformationClass informationClass)
        {
            return FileInformation.GetFileInformation(InformationBytes, 0, informationClass);
        }

        /// <remarks>
        /// Support for pass-through Information Levels must be enabled.
        /// </remarks>
        public void SetFileInformation(FileInformation information)
        {
            InformationBytes = information.GetBytes();
        }

        public override Transaction2SubcommandName SubcommandName
        {
            get
            {
                return Transaction2SubcommandName.TRANS2_QUERY_FILE_INFORMATION;
            }
        }
    }
}