/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;
using Utilities;

namespace SMBLibrary.SMB1
{
    public abstract class Transaction2Subcommand
    {
        public Transaction2Subcommand()
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

        public virtual byte[] GetData(bool isUnicode)
        {
            return new byte[0];
        }

        public abstract Transaction2SubcommandName SubcommandName
        {
            get;
        }

        public static Transaction2Subcommand GetSubcommandRequest(byte[] setup, byte[] parameters, byte[] data, bool isUnicode)
        {
            if (setup.Length == 2)
            {
                Transaction2SubcommandName subcommandName = (Transaction2SubcommandName)LittleEndianConverter.ToUInt16(setup, 0);
                switch (subcommandName)
                {
                    case Transaction2SubcommandName.TRANS2_OPEN2:
                        return new Transaction2Open2Request(parameters, data, isUnicode);

                    case Transaction2SubcommandName.TRANS2_FIND_FIRST2:
                        return new Transaction2FindFirst2Request(parameters, data, isUnicode);

                    case Transaction2SubcommandName.TRANS2_FIND_NEXT2:
                        return new Transaction2FindNext2Request(parameters, data, isUnicode);

                    case Transaction2SubcommandName.TRANS2_QUERY_FS_INFORMATION:
                        return new Transaction2QueryFSInformationRequest(parameters, data, isUnicode);

                    case Transaction2SubcommandName.TRANS2_SET_FS_INFORMATION:
                        return new Transaction2SetFSInformationRequest(parameters, data, isUnicode);

                    case Transaction2SubcommandName.TRANS2_QUERY_PATH_INFORMATION:
                        return new Transaction2QueryPathInformationRequest(parameters, data, isUnicode);

                    case Transaction2SubcommandName.TRANS2_SET_PATH_INFORMATION:
                        return new Transaction2SetPathInformationRequest(parameters, data, isUnicode);

                    case Transaction2SubcommandName.TRANS2_QUERY_FILE_INFORMATION:
                        return new Transaction2QueryFileInformationRequest(parameters, data, isUnicode);

                    case Transaction2SubcommandName.TRANS2_SET_FILE_INFORMATION:
                        return new Transaction2SetFileInformationRequest(parameters, data, isUnicode);

                    case Transaction2SubcommandName.TRANS2_CREATE_DIRECTORY:
                        return new Transaction2CreateDirectoryRequest(parameters, data, isUnicode);

                    case Transaction2SubcommandName.TRANS2_GET_DFS_REFERRAL:
                        return new Transaction2GetDfsReferralRequest(parameters, data);
                }
            }
            throw new InvalidDataException();
        }
    }
}