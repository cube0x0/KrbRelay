/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// NT_TRANSACT_NOTIFY_CHANGE Response
    /// </summary>
    public class NTTransactNotifyChangeResponse : NTTransactSubcommand
    {
        // Parameters:
        public byte[] FileNotifyInformationBytes;

        public NTTransactNotifyChangeResponse() : base()
        {
        }

        public NTTransactNotifyChangeResponse(byte[] parameters) : base()
        {
            FileNotifyInformationBytes = parameters;
        }

        public override byte[] GetParameters(bool isUnicode)
        {
            return FileNotifyInformationBytes;
        }

        public List<FileNotifyInformation> GetFileNotifyInformation()
        {
            return FileNotifyInformation.ReadList(FileNotifyInformationBytes, 0);
        }

        public void SetFileNotifyInformation(List<FileNotifyInformation> notifyInformationList)
        {
            FileNotifyInformationBytes = FileNotifyInformation.GetBytes(notifyInformationList);
        }

        public override NTTransactSubcommandName SubcommandName
        {
            get
            {
                return NTTransactSubcommandName.NT_TRANSACT_NOTIFY_CHANGE;
            }
        }
    }
}