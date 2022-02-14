/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace SMBLibrary.SMB1
{
    public class QueryInformationHelper
    {
        /// <exception cref="SMBLibrary.UnsupportedInformationLevelException"></exception>
        public static FileInformationClass ToFileInformationClass(QueryInformationLevel informationLevel)
        {
            switch (informationLevel)
            {
                case QueryInformationLevel.SMB_QUERY_FILE_BASIC_INFO:
                    return FileInformationClass.FileBasicInformation;

                case QueryInformationLevel.SMB_QUERY_FILE_STANDARD_INFO:
                    return FileInformationClass.FileStandardInformation;

                case QueryInformationLevel.SMB_QUERY_FILE_EA_INFO:
                    return FileInformationClass.FileEaInformation;

                case QueryInformationLevel.SMB_QUERY_FILE_NAME_INFO:
                    return FileInformationClass.FileNameInformation;

                case QueryInformationLevel.SMB_QUERY_FILE_ALL_INFO:
                    return FileInformationClass.FileAllInformation;

                case QueryInformationLevel.SMB_QUERY_FILE_ALT_NAME_INFO:
                    return FileInformationClass.FileAlternateNameInformation;

                case QueryInformationLevel.SMB_QUERY_FILE_STREAM_INFO:
                    return FileInformationClass.FileStreamInformation;

                case QueryInformationLevel.SMB_QUERY_FILE_COMPRESSION_INFO:
                    return FileInformationClass.FileCompressionInformation;

                default:
                    throw new UnsupportedInformationLevelException();
            }
        }

        public static QueryInformation FromFileInformation(FileInformation fileInformation)
        {
            if (fileInformation is FileBasicInformation)
            {
                FileBasicInformation fileBasicInfo = (FileBasicInformation)fileInformation;
                QueryFileBasicInfo result = new QueryFileBasicInfo();
                result.CreationTime = fileBasicInfo.CreationTime;
                result.LastAccessTime = fileBasicInfo.LastAccessTime;
                result.LastWriteTime = fileBasicInfo.LastWriteTime;
                result.LastChangeTime = fileBasicInfo.ChangeTime;
                result.ExtFileAttributes = (ExtendedFileAttributes)fileBasicInfo.FileAttributes;
                return result;
            }
            else if (fileInformation is FileStandardInformation)
            {
                FileStandardInformation fileStandardInfo = (FileStandardInformation)fileInformation;
                QueryFileStandardInfo result = new QueryFileStandardInfo();
                result.AllocationSize = fileStandardInfo.AllocationSize;
                result.EndOfFile = fileStandardInfo.EndOfFile;
                result.DeletePending = fileStandardInfo.DeletePending;
                result.Directory = fileStandardInfo.Directory;
                return result;
            }
            else if (fileInformation is FileEaInformation)
            {
                FileEaInformation fileEAInfo = (FileEaInformation)fileInformation;
                QueryFileEaInfo result = new QueryFileEaInfo();
                result.EaSize = fileEAInfo.EaSize;
                return result;
            }
            else if (fileInformation is FileNameInformation)
            {
                FileNameInformation fileNameInfo = (FileNameInformation)fileInformation;
                QueryFileNameInfo result = new QueryFileNameInfo();
                result.FileName = fileNameInfo.FileName;
                return result;
            }
            else if (fileInformation is FileAllInformation)
            {
                FileAllInformation fileAllInfo = (FileAllInformation)fileInformation;
                QueryFileAllInfo result = new QueryFileAllInfo();
                result.CreationTime = fileAllInfo.BasicInformation.CreationTime;
                result.LastAccessTime = fileAllInfo.BasicInformation.LastAccessTime;
                result.LastWriteTime = fileAllInfo.BasicInformation.LastWriteTime;
                result.LastChangeTime = fileAllInfo.BasicInformation.ChangeTime;
                result.ExtFileAttributes = (ExtendedFileAttributes)fileAllInfo.BasicInformation.FileAttributes;
                result.AllocationSize = fileAllInfo.StandardInformation.AllocationSize;
                result.EndOfFile = fileAllInfo.StandardInformation.EndOfFile;
                result.DeletePending = fileAllInfo.StandardInformation.DeletePending;
                result.Directory = fileAllInfo.StandardInformation.Directory;
                result.EaSize = fileAllInfo.EaInformation.EaSize;
                result.FileName = fileAllInfo.NameInformation.FileName;
                return result;
            }
            else if (fileInformation is FileAlternateNameInformation)
            {
                FileAlternateNameInformation fileAltNameInfo = (FileAlternateNameInformation)fileInformation;
                QueryFileAltNameInfo result = new QueryFileAltNameInfo();
                result.FileName = fileAltNameInfo.FileName;
                return result;
            }
            else if (fileInformation is FileStreamInformation)
            {
                FileStreamInformation fileStreamInfo = (FileStreamInformation)fileInformation;
                QueryFileStreamInfo result = new QueryFileStreamInfo();
                result.Entries.AddRange(fileStreamInfo.Entries);
                return result;
            }
            else if (fileInformation is FileCompressionInformation)
            {
                FileCompressionInformation fileCompressionInfo = (FileCompressionInformation)fileInformation;
                QueryFileCompressionInfo result = new QueryFileCompressionInfo();
                result.CompressedFileSize = fileCompressionInfo.CompressedFileSize;
                result.CompressionFormat = fileCompressionInfo.CompressionFormat;
                result.CompressionUnitShift = fileCompressionInfo.CompressionUnitShift;
                result.ChunkShift = fileCompressionInfo.ChunkShift;
                result.ClusterShift = fileCompressionInfo.ClusterShift;
                result.Reserved = fileCompressionInfo.Reserved;
                return result;
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        /// <exception cref="SMBLibrary.UnsupportedInformationLevelException"></exception>
        public static QueryInformationLevel ToFileInformationLevel(FileInformationClass informationClass)
        {
            switch (informationClass)
            {
                case FileInformationClass.FileBasicInformation:
                    return QueryInformationLevel.SMB_QUERY_FILE_BASIC_INFO;

                case FileInformationClass.FileStandardInformation:
                    return QueryInformationLevel.SMB_QUERY_FILE_STANDARD_INFO;

                case FileInformationClass.FileEaInformation:
                    return QueryInformationLevel.SMB_QUERY_FILE_EA_INFO;

                case FileInformationClass.FileNameInformation:
                    return QueryInformationLevel.SMB_QUERY_FILE_NAME_INFO;

                case FileInformationClass.FileAllInformation:
                    return QueryInformationLevel.SMB_QUERY_FILE_ALL_INFO;

                case FileInformationClass.FileAlternateNameInformation:
                    return QueryInformationLevel.SMB_QUERY_FILE_ALT_NAME_INFO;

                case FileInformationClass.FileStreamInformation:
                    return QueryInformationLevel.SMB_QUERY_FILE_STREAM_INFO;

                case FileInformationClass.FileCompressionInformation:
                    return QueryInformationLevel.SMB_QUERY_FILE_COMPRESSION_INFO;

                default:
                    throw new UnsupportedInformationLevelException();
            }
        }

        public static FileInformation ToFileInformation(QueryInformation queryInformation)
        {
            if (queryInformation is QueryFileBasicInfo)
            {
                QueryFileBasicInfo queryFileBasicInfo = (QueryFileBasicInfo)queryInformation;
                FileBasicInformation result = new FileBasicInformation();
                result.CreationTime = queryFileBasicInfo.CreationTime;
                result.LastAccessTime = queryFileBasicInfo.LastAccessTime;
                result.LastWriteTime = queryFileBasicInfo.LastWriteTime;
                result.ChangeTime = queryFileBasicInfo.LastChangeTime;
                result.FileAttributes = (FileAttributes)queryFileBasicInfo.ExtFileAttributes;
                return result;
            }
            else if (queryInformation is QueryFileStandardInfo)
            {
                QueryFileStandardInfo queryFileStandardInfo = (QueryFileStandardInfo)queryInformation;
                FileStandardInformation result = new FileStandardInformation();
                result.AllocationSize = queryFileStandardInfo.AllocationSize;
                result.EndOfFile = queryFileStandardInfo.EndOfFile;
                result.DeletePending = queryFileStandardInfo.DeletePending;
                result.Directory = queryFileStandardInfo.Directory;
                return result;
            }
            else if (queryInformation is QueryFileEaInfo)
            {
                QueryFileEaInfo queryFileEaInfo = (QueryFileEaInfo)queryInformation;
                FileEaInformation result = new FileEaInformation();
                result.EaSize = queryFileEaInfo.EaSize;
                return result;
            }
            else if (queryInformation is QueryFileNameInfo)
            {
                QueryFileNameInfo queryFileNameInfo = (QueryFileNameInfo)queryInformation;
                FileNameInformation result = new FileNameInformation();
                result.FileName = queryFileNameInfo.FileName;
                return result;
            }
            else if (queryInformation is QueryFileAllInfo)
            {
                QueryFileAllInfo queryFileAllInfo = (QueryFileAllInfo)queryInformation;
                FileAllInformation result = new FileAllInformation();
                result.BasicInformation.CreationTime = queryFileAllInfo.CreationTime;
                result.BasicInformation.LastAccessTime = queryFileAllInfo.LastAccessTime;
                result.BasicInformation.LastWriteTime = queryFileAllInfo.LastWriteTime;
                result.BasicInformation.ChangeTime = queryFileAllInfo.LastChangeTime;
                result.BasicInformation.FileAttributes = (FileAttributes)queryFileAllInfo.ExtFileAttributes;
                result.StandardInformation.AllocationSize = queryFileAllInfo.AllocationSize;
                result.StandardInformation.EndOfFile = queryFileAllInfo.EndOfFile;
                result.StandardInformation.DeletePending = queryFileAllInfo.DeletePending;
                result.StandardInformation.Directory = queryFileAllInfo.Directory;
                result.EaInformation.EaSize = queryFileAllInfo.EaSize;
                result.NameInformation.FileName = queryFileAllInfo.FileName;
                return result;
            }
            else if (queryInformation is QueryFileAltNameInfo)
            {
                QueryFileAltNameInfo queryFileAltNameInfo = (QueryFileAltNameInfo)queryInformation;
                FileAlternateNameInformation result = new FileAlternateNameInformation();
                result.FileName = queryFileAltNameInfo.FileName;
                return result;
            }
            else if (queryInformation is QueryFileStreamInfo)
            {
                QueryFileStreamInfo queryFileStreamInfo = (QueryFileStreamInfo)queryInformation;
                FileStreamInformation result = new FileStreamInformation();
                result.Entries.AddRange(queryFileStreamInfo.Entries);
                return result;
            }
            else if (queryInformation is QueryFileCompressionInfo)
            {
                QueryFileCompressionInfo queryFileCompressionInfo = (QueryFileCompressionInfo)queryInformation;
                FileCompressionInformation result = new FileCompressionInformation();
                result.CompressedFileSize = queryFileCompressionInfo.CompressedFileSize;
                result.CompressionFormat = queryFileCompressionInfo.CompressionFormat;
                result.CompressionUnitShift = queryFileCompressionInfo.CompressionUnitShift;
                result.ChunkShift = queryFileCompressionInfo.ChunkShift;
                result.ClusterShift = queryFileCompressionInfo.ClusterShift;
                result.Reserved = queryFileCompressionInfo.Reserved;
                return result;
            }
            else
            {
                throw new NotImplementedException();
            }
        }
    }
}