/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace SMBLibrary.SMB1
{
    public class QueryFSInformationHelper
    {
        /// <exception cref="SMBLibrary.UnsupportedInformationLevelException"></exception>
        public static FileSystemInformationClass ToFileSystemInformationClass(QueryFSInformationLevel informationLevel)
        {
            switch (informationLevel)
            {
                case QueryFSInformationLevel.SMB_QUERY_FS_VOLUME_INFO:
                    return FileSystemInformationClass.FileFsVolumeInformation;

                case QueryFSInformationLevel.SMB_QUERY_FS_SIZE_INFO:
                    return FileSystemInformationClass.FileFsSizeInformation;

                case QueryFSInformationLevel.SMB_QUERY_FS_DEVICE_INFO:
                    return FileSystemInformationClass.FileFsDeviceInformation;

                case QueryFSInformationLevel.SMB_QUERY_FS_ATTRIBUTE_INFO:
                    return FileSystemInformationClass.FileFsAttributeInformation;

                default:
                    throw new UnsupportedInformationLevelException();
            }
        }

        public static QueryFSInformation FromFileSystemInformation(FileSystemInformation fsInfo)
        {
            if (fsInfo is FileFsVolumeInformation)
            {
                FileFsVolumeInformation volumeInfo = (FileFsVolumeInformation)fsInfo;
                QueryFSVolumeInfo result = new QueryFSVolumeInfo();
                result.VolumeCreationTime = volumeInfo.VolumeCreationTime;
                result.SerialNumber = volumeInfo.VolumeSerialNumber;
                result.VolumeLabel = volumeInfo.VolumeLabel;
                return result;
            }
            else if (fsInfo is FileFsSizeInformation)
            {
                FileFsSizeInformation fsSizeInfo = (FileFsSizeInformation)fsInfo;
                QueryFSSizeInfo result = new QueryFSSizeInfo();
                result.TotalAllocationUnits = fsSizeInfo.TotalAllocationUnits;
                result.TotalFreeAllocationUnits = fsSizeInfo.AvailableAllocationUnits;
                result.BytesPerSector = fsSizeInfo.BytesPerSector;
                result.SectorsPerAllocationUnit = fsSizeInfo.SectorsPerAllocationUnit;
                return result;
            }
            else if (fsInfo is FileFsDeviceInformation)
            {
                FileFsDeviceInformation fsDeviceInfo = (FileFsDeviceInformation)fsInfo;
                QueryFSDeviceInfo result = new QueryFSDeviceInfo();
                result.DeviceType = fsDeviceInfo.DeviceType;
                result.DeviceCharacteristics = fsDeviceInfo.Characteristics;
                return result;
            }
            else if (fsInfo is FileFsAttributeInformation)
            {
                FileFsAttributeInformation fsAttributeInfo = (FileFsAttributeInformation)fsInfo;
                QueryFSAttibuteInfo result = new QueryFSAttibuteInfo();
                result.FileSystemAttributes = fsAttributeInfo.FileSystemAttributes;
                result.MaxFileNameLengthInBytes = fsAttributeInfo.MaximumComponentNameLength;
                result.FileSystemName = fsAttributeInfo.FileSystemName;
                return result;
            }
            else
            {
                throw new NotImplementedException();
            }
        }
    }
}