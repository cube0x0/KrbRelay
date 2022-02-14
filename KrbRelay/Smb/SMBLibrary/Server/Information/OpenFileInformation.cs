/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;

namespace SMBLibrary.Server
{
    public class OpenFileInformation
    {
        public string ShareName;
        public string Path;
        public FileAccess FileAccess;
        public DateTime OpenedDT;

        public OpenFileInformation(string shareName, string path, FileAccess fileAccess, DateTime openedDT)
        {
            ShareName = shareName;
            Path = path;
            FileAccess = fileAccess;
            OpenedDT = openedDT;
        }
    }
}