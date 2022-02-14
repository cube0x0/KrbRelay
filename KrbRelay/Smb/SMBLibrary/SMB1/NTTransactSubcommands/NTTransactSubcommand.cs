/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;

namespace SMBLibrary.SMB1
{
    public abstract class NTTransactSubcommand
    {
        public NTTransactSubcommand()
        {
        }

        public virtual byte[] GetSetup()
        {
            return new byte[0];
        }

        public virtual byte[] GetParameters(bool isUnicode)
        {
            return new byte[0];
        }

        public virtual byte[] GetData()
        {
            return new byte[0];
        }

        public abstract NTTransactSubcommandName SubcommandName
        {
            get;
        }

        public static NTTransactSubcommand GetSubcommandRequest(NTTransactSubcommandName subcommandName, byte[] setup, byte[] parameters, byte[] data, bool isUnicode)
        {
            switch (subcommandName)
            {
                case NTTransactSubcommandName.NT_TRANSACT_CREATE:
                    return new NTTransactCreateRequest(parameters, data, isUnicode);

                case NTTransactSubcommandName.NT_TRANSACT_IOCTL:
                    return new NTTransactIOCTLRequest(setup, data);

                case NTTransactSubcommandName.NT_TRANSACT_SET_SECURITY_DESC:
                    return new NTTransactSetSecurityDescriptorRequest(parameters, data);

                case NTTransactSubcommandName.NT_TRANSACT_NOTIFY_CHANGE:
                    return new NTTransactNotifyChangeRequest(setup);

                case NTTransactSubcommandName.NT_TRANSACT_QUERY_SECURITY_DESC:
                    return new NTTransactQuerySecurityDescriptorRequest(parameters);
            }
            throw new InvalidDataException();
        }
    }
}