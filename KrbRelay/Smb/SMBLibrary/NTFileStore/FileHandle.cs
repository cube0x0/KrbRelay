/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;

namespace SMBLibrary
{
    public class FileHandle
    {
        public string Path;
        public bool IsDirectory;
        public Stream Stream;
        public bool DeleteOnClose;

        public FileHandle(string path, bool isDirectory, Stream stream, bool deleteOnClose)
        {
            Path = path;
            IsDirectory = isDirectory;
            Stream = stream;
            DeleteOnClose = deleteOnClose;
        }
    }
}