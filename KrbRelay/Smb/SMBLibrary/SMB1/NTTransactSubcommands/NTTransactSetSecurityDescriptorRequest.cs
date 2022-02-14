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
    /// NT_TRANSACT_SET_SECURITY_DESC Request
    /// </summary>
    public class NTTransactSetSecurityDescriptorRequest : NTTransactSubcommand
    {
        public const int ParametersLength = 8;

        // Parameters:
        public ushort FID;

        public ushort Reserved;
        public SecurityInformation SecurityInformation;

        // Data:
        public SecurityDescriptor SecurityDescriptor;

        public NTTransactSetSecurityDescriptorRequest()
        {
        }

        public NTTransactSetSecurityDescriptorRequest(byte[] parameters, byte[] data)
        {
            FID = LittleEndianConverter.ToUInt16(parameters, 0);
            Reserved = LittleEndianConverter.ToUInt16(parameters, 2);
            SecurityInformation = (SecurityInformation)LittleEndianConverter.ToUInt32(parameters, 4);

            SecurityDescriptor = new SecurityDescriptor(data, 0);
        }

        public override byte[] GetParameters(bool isUnicode)
        {
            byte[] parameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(parameters, 0, FID);
            LittleEndianWriter.WriteUInt16(parameters, 2, Reserved);
            LittleEndianWriter.WriteUInt32(parameters, 4, (uint)SecurityInformation);
            return parameters;
        }

        public override byte[] GetData()
        {
            return SecurityDescriptor.GetBytes();
        }

        public override NTTransactSubcommandName SubcommandName
        {
            get
            {
                return NTTransactSubcommandName.NT_TRANSACT_SET_SECURITY_DESC;
            }
        }
    }
}