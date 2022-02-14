/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.4.5 - FileAlternateNameInformation
    /// </summary>
    public class FileAlternateNameInformation : FileNameInformation
    {
        public FileAlternateNameInformation() : base()
        {
        }

        public FileAlternateNameInformation(byte[] buffer, int offset) : base(buffer, offset)
        {
        }

        public override FileInformationClass FileInformationClass
        {
            get
            {
                return FileInformationClass.FileAlternateNameInformation;
            }
        }
    }
}