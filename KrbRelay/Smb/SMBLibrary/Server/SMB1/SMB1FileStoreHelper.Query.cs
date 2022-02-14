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
        public static NTStatus GetFileInformation(out QueryInformation result, INTFileStore fileStore, string path, QueryInformationLevel informationLevel, SecurityContext securityContext)
        {
            object handle;
            FileStatus fileStatus;
            NTStatus openStatus = fileStore.CreateFile(out handle, out fileStatus, path, (AccessMask)FileAccessMask.FILE_READ_ATTRIBUTES, 0, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, 0, securityContext);
            if (openStatus != NTStatus.STATUS_SUCCESS)
            {
                result = null;
                return openStatus;
            }
            NTStatus returnStatus = GetFileInformation(out result, fileStore, handle, informationLevel);
            fileStore.CloseFile(handle);
            return returnStatus;
        }

        public static NTStatus GetFileInformation(out FileInformation result, INTFileStore fileStore, string path, FileInformationClass informationClass, SecurityContext securityContext)
        {
            object handle;
            FileStatus fileStatus;
            NTStatus openStatus = fileStore.CreateFile(out handle, out fileStatus, path, (AccessMask)FileAccessMask.FILE_READ_ATTRIBUTES, 0, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, 0, securityContext);
            if (openStatus != NTStatus.STATUS_SUCCESS)
            {
                result = null;
                return openStatus;
            }
            NTStatus returnStatus = fileStore.GetFileInformation(out result, handle, informationClass);
            fileStore.CloseFile(handle);
            return returnStatus;
        }

        public static NTStatus GetFileInformation(out QueryInformation result, INTFileStore fileStore, object handle, QueryInformationLevel informationLevel)
        {
            result = null;
            FileInformationClass informationClass;
            try
            {
                informationClass = QueryInformationHelper.ToFileInformationClass(informationLevel);
            }
            catch (UnsupportedInformationLevelException)
            {
                return NTStatus.STATUS_OS2_INVALID_LEVEL;
            }

            FileInformation fileInformation;
            NTStatus status = fileStore.GetFileInformation(out fileInformation, handle, informationClass);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return status;
            }

            result = QueryInformationHelper.FromFileInformation(fileInformation);
            return NTStatus.STATUS_SUCCESS;
        }
    }
}