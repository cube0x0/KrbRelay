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
    /// NT_TRANSACT_QUERY_SECURITY_DESC Request
    /// </summary>
    public class NTTransactQuerySecurityDescriptorRequest : NTTransactSubcommand
    {
        public const int ParametersLength = 8;

        // Parameters:
        public ushort FID;

        public ushort Reserved;
        public SecurityInformation SecurityInfoFields;

        public NTTransactQuerySecurityDescriptorRequest()
        {
        }

        public NTTransactQuerySecurityDescriptorRequest(byte[] parameters)
        {
            FID = LittleEndianConverter.ToUInt16(parameters, 0);
            Reserved = LittleEndianConverter.ToUInt16(parameters, 2);
            SecurityInfoFields = (SecurityInformation)LittleEndianConverter.ToUInt32(parameters, 4);
        }

        public override byte[] GetParameters(bool isUnicode)
        {
            byte[] parameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(parameters, 0, FID);
            LittleEndianWriter.WriteUInt16(parameters, 2, Reserved);
            LittleEndianWriter.WriteUInt32(parameters, 4, (uint)SecurityInfoFields);
            return parameters;
        }

        public override NTTransactSubcommandName SubcommandName
        {
            get
            {
                return NTTransactSubcommandName.NT_TRANSACT_QUERY_SECURITY_DESC;
            }
        }
    }
}