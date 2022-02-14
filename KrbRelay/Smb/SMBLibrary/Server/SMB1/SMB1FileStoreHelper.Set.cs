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
        public static NTStatus SetFileInformation(INTFileStore fileStore, object handle, SetInformation information)
        {
            FileInformation fileInformation = SetInformationHelper.ToFileInformation(information);
            return fileStore.SetFileInformation(handle, fileInformation);
        }
    }
}