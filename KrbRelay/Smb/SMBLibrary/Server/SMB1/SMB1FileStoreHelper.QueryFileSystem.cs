/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB1;

namespace SMBLibrary.Server.SMB1
{
    internal partial class SMB1FileStoreHelper
    {
        public static NTStatus GetFileSystemInformation(out QueryFSInformation result, INTFileStore fileStore, QueryFSInformationLevel informationLevel)
        {
            result = null;
            FileSystemInformationClass informationClass;
            try
            {
                informationClass = QueryFSInformationHelper.ToFileSystemInformationClass(informationLevel);
            }
            catch (UnsupportedInformationLevelException)
            {
                return NTStatus.STATUS_OS2_INVALID_LEVEL;
            }

            FileSystemInformation fsInfo;
            NTStatus status = fileStore.GetFileSystemInformation(out fsInfo, informationClass);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return status;
            }

            result = QueryFSInformationHelper.FromFileSystemInformation(fsInfo);
            return NTStatus.STATUS_SUCCESS;
        }
    }
}