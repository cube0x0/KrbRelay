/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace SMBLibrary.Server
{
    public class ServerPathUtils
    {
        /// <param name="path">UNC path, e.g. '\\192.168.1.1\Shared'</param>
        /// <returns>e.g. \Shared</returns>
        public static string GetRelativeServerPath(string path)
        {
            if (path.StartsWith(@"\\"))
            {
                int index = path.IndexOf('\\', 2);
                if (index > 0)
                {
                    return path.Substring(index);
                }
                else
                {
                    return String.Empty;
                }
            }
            return path;
        }

        /// <param name="path">UNC path, e.g. '\\192.168.1.1\Shared\*'</param>
        /// <returns>e.g. \*</returns>
        public static string GetRelativeSharePath(string path)
        {
            string relativePath = GetRelativeServerPath(path);
            int index = relativePath.IndexOf('\\', 1);
            if (index > 0)
            {
                return path.Substring(index);
            }
            else
            {
                return @"\";
            }
        }

        public static string GetShareName(string path)
        {
            string relativePath = GetRelativeServerPath(path);
            if (relativePath.StartsWith(@"\"))
            {
                relativePath = relativePath.Substring(1);
            }

            int indexOfSeparator = relativePath.IndexOf(@"\");
            if (indexOfSeparator >= 0)
            {
                relativePath = relativePath.Substring(0, indexOfSeparator);
            }
            return relativePath;
        }
    }
}