/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    public abstract class QueryFSInformation
    {
        public abstract byte[] GetBytes(bool isUnicode);

        public abstract int Length
        {
            get;
        }

        public abstract QueryFSInformationLevel InformationLevel
        {
            get;
        }

        public static QueryFSInformation GetQueryFSInformation(byte[] buffer, QueryFSInformationLevel informationLevel, bool isUnicode)
        {
            switch (informationLevel)
            {
                case QueryFSInformationLevel.SMB_QUERY_FS_VOLUME_INFO:
                    return new QueryFSVolumeInfo(buffer, 0);

                case QueryFSInformationLevel.SMB_QUERY_FS_SIZE_INFO:
                    return new QueryFSSizeInfo(buffer, 0);

                case QueryFSInformationLevel.SMB_QUERY_FS_DEVICE_INFO:
                    return new QueryFSDeviceInfo(buffer, 0);

                case QueryFSInformationLevel.SMB_QUERY_FS_ATTRIBUTE_INFO:
                    return new QueryFSAttibuteInfo(buffer, 0);

                default:
                    throw new UnsupportedInformationLevelException();
            }
        }
    }
}