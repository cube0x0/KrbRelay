/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;

namespace SMBLibrary.SMB1
{
    public class FindInformationHelper
    {
        /// <exception cref="SMBLibrary.UnsupportedInformationLevelException"></exception>
        public static FileInformationClass ToFileInformationClass(FindInformationLevel informationLevel)
        {
            switch (informationLevel)
            {
                case FindInformationLevel.SMB_FIND_FILE_DIRECTORY_INFO:
                    return FileInformationClass.FileDirectoryInformation;

                case FindInformationLevel.SMB_FIND_FILE_FULL_DIRECTORY_INFO:
                    return FileInformationClass.FileFullDirectoryInformation;

                case FindInformationLevel.SMB_FIND_FILE_NAMES_INFO:
                    return FileInformationClass.FileNamesInformation;

                case FindInformationLevel.SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
                    return FileInformationClass.FileBothDirectoryInformation;

                case FindInformationLevel.SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO:
                    return FileInformationClass.FileIdFullDirectoryInformation;

                case FindInformationLevel.SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO:
                    return FileInformationClass.FileIdBothDirectoryInformation;

                default:
                    throw new UnsupportedInformationLevelException();
            }
        }

        /// <exception cref="SMBLibrary.UnsupportedInformationLevelException"></exception>
        public static FindInformationList ToFindInformationList(List<QueryDirectoryFileInformation> entries, bool isUnicode, int maxLength)
        {
            FindInformationList result = new FindInformationList();
            int pageLength = 0;
            for (int index = 0; index < entries.Count; index++)
            {
                FindInformation infoEntry = ToFindInformation(entries[index]);
                int entryLength = infoEntry.GetLength(isUnicode);
                if (pageLength + entryLength <= maxLength)
                {
                    result.Add(infoEntry);
                    pageLength += entryLength;
                }
                else
                {
                    break;
                }
            }
            return result;
        }

        /// <exception cref="SMBLibrary.UnsupportedInformationLevelException"></exception>
        public static FindInformation ToFindInformation(QueryDirectoryFileInformation fileInformation)
        {
            if (fileInformation is FileDirectoryInformation)
            {
                FileDirectoryInformation fileDirectoryInfo = (FileDirectoryInformation)fileInformation;
                FindFileDirectoryInfo result = new FindFileDirectoryInfo();
                result.FileIndex = fileDirectoryInfo.FileIndex;
                result.CreationTime = fileDirectoryInfo.CreationTime;
                result.LastAccessTime = fileDirectoryInfo.LastAccessTime;
                result.LastWriteTime = fileDirectoryInfo.LastWriteTime;
                result.LastAttrChangeTime = fileDirectoryInfo.LastWriteTime;
                result.EndOfFile = fileDirectoryInfo.EndOfFile;
                result.AllocationSize = fileDirectoryInfo.AllocationSize;
                result.ExtFileAttributes = (ExtendedFileAttributes)fileDirectoryInfo.FileAttributes;
                result.FileName = fileDirectoryInfo.FileName;
                return result;
            }
            else if (fileInformation is FileFullDirectoryInformation)
            {
                FileFullDirectoryInformation fileFullDirectoryInfo = (FileFullDirectoryInformation)fileInformation;
                FindFileFullDirectoryInfo result = new FindFileFullDirectoryInfo();
                result.FileIndex = fileFullDirectoryInfo.FileIndex;
                result.CreationTime = fileFullDirectoryInfo.CreationTime;
                result.LastAccessTime = fileFullDirectoryInfo.LastAccessTime;
                result.LastWriteTime = fileFullDirectoryInfo.LastWriteTime;
                result.LastAttrChangeTime = fileFullDirectoryInfo.LastWriteTime;
                result.EndOfFile = fileFullDirectoryInfo.EndOfFile;
                result.AllocationSize = fileFullDirectoryInfo.AllocationSize;
                result.ExtFileAttributes = (ExtendedFileAttributes)fileFullDirectoryInfo.FileAttributes;
                result.EASize = fileFullDirectoryInfo.EaSize;
                result.FileName = fileFullDirectoryInfo.FileName;
                return result;
            }
            else if (fileInformation is FileNamesInformation)
            {
                FileNamesInformation fileNamesInfo = (FileNamesInformation)fileInformation;
                FindFileNamesInfo result = new FindFileNamesInfo();
                result.FileIndex = fileNamesInfo.FileIndex;
                result.FileName = fileNamesInfo.FileName;
                return result;
            }
            else if (fileInformation is FileBothDirectoryInformation)
            {
                FileBothDirectoryInformation fileBothDirectoryInfo = (FileBothDirectoryInformation)fileInformation;
                FindFileBothDirectoryInfo result = new FindFileBothDirectoryInfo();
                result.FileIndex = fileBothDirectoryInfo.FileIndex;
                result.CreationTime = fileBothDirectoryInfo.CreationTime;
                result.LastAccessTime = fileBothDirectoryInfo.LastAccessTime;
                result.LastWriteTime = fileBothDirectoryInfo.LastWriteTime;
                result.LastChangeTime = fileBothDirectoryInfo.LastWriteTime;
                result.EndOfFile = fileBothDirectoryInfo.EndOfFile;
                result.AllocationSize = fileBothDirectoryInfo.AllocationSize;
                result.ExtFileAttributes = (ExtendedFileAttributes)fileBothDirectoryInfo.FileAttributes;
                result.EASize = fileBothDirectoryInfo.EaSize;
                result.Reserved = fileBothDirectoryInfo.Reserved;
                result.ShortName = fileBothDirectoryInfo.ShortName;
                result.FileName = fileBothDirectoryInfo.FileName;
                return result;
            }
            else if (fileInformation is FileIdFullDirectoryInformation)
            {
                FileIdFullDirectoryInformation fileIDFullDirectoryInfo = (FileIdFullDirectoryInformation)fileInformation;
                FindFileIDFullDirectoryInfo result = new FindFileIDFullDirectoryInfo();
                result.FileIndex = fileIDFullDirectoryInfo.FileIndex;
                result.CreationTime = fileIDFullDirectoryInfo.CreationTime;
                result.LastAccessTime = fileIDFullDirectoryInfo.LastAccessTime;
                result.LastWriteTime = fileIDFullDirectoryInfo.LastWriteTime;
                result.LastAttrChangeTime = fileIDFullDirectoryInfo.LastWriteTime;
                result.EndOfFile = fileIDFullDirectoryInfo.EndOfFile;
                result.AllocationSize = fileIDFullDirectoryInfo.AllocationSize;
                result.ExtFileAttributes = (ExtendedFileAttributes)fileIDFullDirectoryInfo.FileAttributes;
                result.EASize = fileIDFullDirectoryInfo.EaSize;
                result.Reserved = fileIDFullDirectoryInfo.Reserved;
                result.FileID = fileIDFullDirectoryInfo.FileId;
                result.FileName = fileIDFullDirectoryInfo.FileName;
                return result;
            }
            else if (fileInformation is FileIdBothDirectoryInformation)
            {
                FileIdBothDirectoryInformation fileIDBothDirectoryInfo = (FileIdBothDirectoryInformation)fileInformation;
                FindFileIDBothDirectoryInfo result = new FindFileIDBothDirectoryInfo();
                result.FileIndex = fileIDBothDirectoryInfo.FileIndex;
                result.CreationTime = fileIDBothDirectoryInfo.CreationTime;
                result.LastAccessTime = fileIDBothDirectoryInfo.LastAccessTime;
                result.LastWriteTime = fileIDBothDirectoryInfo.LastWriteTime;
                result.LastChangeTime = fileIDBothDirectoryInfo.LastWriteTime;
                result.EndOfFile = fileIDBothDirectoryInfo.EndOfFile;
                result.AllocationSize = fileIDBothDirectoryInfo.AllocationSize;
                result.ExtFileAttributes = (ExtendedFileAttributes)fileIDBothDirectoryInfo.FileAttributes;
                result.EASize = fileIDBothDirectoryInfo.EaSize;
                result.Reserved = fileIDBothDirectoryInfo.Reserved1;
                result.ShortName = fileIDBothDirectoryInfo.ShortName;
                result.Reserved2 = fileIDBothDirectoryInfo.Reserved2;
                result.FileID = fileIDBothDirectoryInfo.FileId;
                result.FileName = fileIDBothDirectoryInfo.FileName;
                return result;
            }
            else
            {
                throw new NotImplementedException();
            }
        }
    }
}