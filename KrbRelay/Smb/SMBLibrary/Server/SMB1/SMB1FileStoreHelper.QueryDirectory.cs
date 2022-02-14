/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;

namespace SMBLibrary.Server.SMB1
{
    internal partial class SMB1FileStoreHelper
    {
        // Filename pattern examples:
        // '\Directory' - Get the directory entry
        // '\Directory\*' - List the directory files
        // '\Directory\s*' - List the directory files starting with s (cmd.exe will use this syntax when entering 's' and hitting tab for autocomplete)
        // '\Directory\<.inf' (Update driver will use this syntax)
        // '\Directory\exefile"*' (cmd.exe will use this syntax when entering an exe without its extension, explorer will use this opening a directory from the run menu)
        /// <param name="fileNamePattern">The filename pattern to search for. This field MAY contain wildcard characters</param>
        /// <exception cref="System.UnauthorizedAccessException"></exception>
        public static NTStatus QueryDirectory(out List<QueryDirectoryFileInformation> result, INTFileStore fileStore, string fileNamePattern, FileInformationClass fileInformation, SecurityContext securityContext)
        {
            int separatorIndex = fileNamePattern.LastIndexOf('\\');
            if (separatorIndex >= 0)
            {
                string path = fileNamePattern.Substring(0, separatorIndex + 1);
                string fileName = fileNamePattern.Substring(separatorIndex + 1);
                object handle;
                FileStatus fileStatus;
                DirectoryAccessMask accessMask = DirectoryAccessMask.FILE_LIST_DIRECTORY | DirectoryAccessMask.FILE_TRAVERSE | DirectoryAccessMask.SYNCHRONIZE;
                CreateOptions createOptions = CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT;
                NTStatus status = fileStore.CreateFile(out handle, out fileStatus, path, (AccessMask)accessMask, 0, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, createOptions, securityContext);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    result = null;
                    return status;
                }
                status = fileStore.QueryDirectory(out result, handle, fileName, fileInformation);
                fileStore.CloseFile(handle);
                return status;
            }
            else
            {
                result = null;
                return NTStatus.STATUS_INVALID_PARAMETER;
            }
        }
    }
}