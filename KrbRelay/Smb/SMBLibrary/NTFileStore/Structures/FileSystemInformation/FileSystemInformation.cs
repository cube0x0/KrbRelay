/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary
{
    public abstract class FileSystemInformation
    {
        public abstract void WriteBytes(byte[] buffer, int offset);

        public byte[] GetBytes()
        {
            byte[] buffer = new byte[this.Length];
            WriteBytes(buffer, 0);
            return buffer;
        }

        public abstract FileSystemInformationClass FileSystemInformationClass
        {
            get;
        }

        public abstract int Length
        {
            get;
        }

        public static FileSystemInformation GetFileSystemInformation(byte[] buffer, int offset, FileSystemInformationClass informationClass)
        {
            switch (informationClass)
            {
                case FileSystemInformationClass.FileFsVolumeInformation:
                    return new FileFsVolumeInformation(buffer, offset);

                case FileSystemInformationClass.FileFsSizeInformation:
                    return new FileFsSizeInformation(buffer, offset);

                case FileSystemInformationClass.FileFsDeviceInformation:
                    return new FileFsDeviceInformation(buffer, offset);

                case FileSystemInformationClass.FileFsAttributeInformation:
                    return new FileFsAttributeInformation(buffer, offset);

                case FileSystemInformationClass.FileFsControlInformation:
                    return new FileFsControlInformation(buffer, offset);

                case FileSystemInformationClass.FileFsFullSizeInformation:
                    return new FileFsFullSizeInformation(buffer, offset);

                case FileSystemInformationClass.FileFsObjectIdInformation:
                    return new FileFsObjectIdInformation(buffer, offset);

                case FileSystemInformationClass.FileFsSectorSizeInformation:
                    return new FileFsSectorSizeInformation(buffer, offset);

                default:
                    throw new UnsupportedInformationLevelException();
            }
        }
    }
}