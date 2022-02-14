/* Copyright (C) 2017-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace SMBLibrary
{
    public abstract class FileInformation
    {
        public abstract void WriteBytes(byte[] buffer, int offset);

        public byte[] GetBytes()
        {
            byte[] buffer = new byte[this.Length];
            WriteBytes(buffer, 0);
            return buffer;
        }

        public abstract FileInformationClass FileInformationClass
        {
            get;
        }

        public abstract int Length
        {
            get;
        }

        public static FileInformation GetFileInformation(byte[] buffer, int offset, FileInformationClass informationClass)
        {
            switch (informationClass)
            {
                case FileInformationClass.FileBasicInformation:
                    return new FileBasicInformation(buffer, offset);

                case FileInformationClass.FileStandardInformation:
                    return new FileStandardInformation(buffer, offset);

                case FileInformationClass.FileInternalInformation:
                    return new FileInternalInformation(buffer, offset);

                case FileInformationClass.FileEaInformation:
                    return new FileEaInformation(buffer, offset);

                case FileInformationClass.FileAccessInformation:
                    return new FileAccessInformation(buffer, offset);

                case FileInformationClass.FileRenameInformation:
                    return new FileRenameInformationType2(buffer, offset);

                case FileInformationClass.FileLinkInformation:
                    return new FileLinkInformationType2(buffer, offset);

                case FileInformationClass.FileNamesInformation:
                    throw new NotImplementedException();
                case FileInformationClass.FileDispositionInformation:
                    return new FileDispositionInformation(buffer, offset);

                case FileInformationClass.FilePositionInformation:
                    return new FilePositionInformation(buffer, offset);

                case FileInformationClass.FileFullEaInformation:
                    return new FileFullEAInformation(buffer, offset);

                case FileInformationClass.FileModeInformation:
                    return new FileModeInformation(buffer, offset);

                case FileInformationClass.FileAlignmentInformation:
                    return new FileAlignmentInformation(buffer, offset);

                case FileInformationClass.FileAllInformation:
                    return new FileAllInformation(buffer, offset);

                case FileInformationClass.FileAllocationInformation:
                    return new FileAllocationInformation(buffer, offset);

                case FileInformationClass.FileEndOfFileInformation:
                    return new FileEndOfFileInformation(buffer, offset);

                case FileInformationClass.FileAlternateNameInformation:
                    return new FileAlternateNameInformation(buffer, offset);

                case FileInformationClass.FileStreamInformation:
                    return new FileStreamInformation(buffer, offset);

                case FileInformationClass.FilePipeInformation:
                    throw new NotImplementedException();
                case FileInformationClass.FilePipeLocalInformation:
                    throw new NotImplementedException();
                case FileInformationClass.FilePipeRemoteInformation:
                    throw new NotImplementedException();
                case FileInformationClass.FileCompressionInformation:
                    return new FileCompressionInformation(buffer, offset);

                case FileInformationClass.FileNetworkOpenInformation:
                    return new FileNetworkOpenInformation(buffer, offset);

                case FileInformationClass.FileAttributeTagInformation:
                    throw new NotImplementedException();
                case FileInformationClass.FileValidDataLengthInformation:
                    return new FileValidDataLengthInformation(buffer, offset);

                case FileInformationClass.FileShortNameInformation:
                    throw new NotImplementedException();
                default:
                    throw new UnsupportedInformationLevelException(String.Format("Unsupported information class: {0}", informationClass));
            }
        }
    }
}