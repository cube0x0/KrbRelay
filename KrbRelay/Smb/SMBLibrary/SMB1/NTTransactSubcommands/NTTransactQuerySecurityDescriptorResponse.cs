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
    /// NT_TRANSACT_QUERY_SECURITY_DESC Response
    /// </summary>
    public class NTTransactQuerySecurityDescriptorResponse : NTTransactSubcommand
    {
        public const int ParametersLength = 4;

        // Parameters:
        public uint LengthNeeded;

        // Data
        public SecurityDescriptor SecurityDescriptor; // We might return STATUS_BUFFER_TOO_SMALL without the SecurityDescriptor field

        public NTTransactQuerySecurityDescriptorResponse()
        {
        }

        public NTTransactQuerySecurityDescriptorResponse(byte[] parameters, byte[] data)
        {
            LengthNeeded = LittleEndianConverter.ToUInt32(parameters, 0);

            if (data.Length == LengthNeeded)
            {
                SecurityDescriptor = new SecurityDescriptor(data, 0);
            }
        }

        public override byte[] GetParameters(bool isUnicode)
        {
            byte[] parameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt32(parameters, 0, LengthNeeded);
            return parameters;
        }

        public override byte[] GetData()
        {
            if (SecurityDescriptor != null)
            {
                return SecurityDescriptor.GetBytes();
            }
            else
            {
                return new byte[0];
            }
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