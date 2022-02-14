/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;

namespace SMBLibrary.Server
{
    public class SMBShareCollection : List<FileSystemShare>
    {
        public bool Contains(string shareName, StringComparison comparisonType)
        {
            return (this.IndexOf(shareName, comparisonType) != -1);
        }

        public int IndexOf(string shareName, StringComparison comparisonType)
        {
            for (int index = 0; index < this.Count; index++)
            {
                if (this[index].Name.Equals(shareName, comparisonType))
                {
                    return index;
                }
            }

            return -1;
        }

        public List<string> ListShares()
        {
            List<string> result = new List<string>();
            foreach (FileSystemShare share in this)
            {
                result.Add(share.Name);
            }
            return result;
        }

        /// <param name="shareName">e.g. \Shared</param>
        public FileSystemShare GetShareFromName(string shareName)
        {
            int index = IndexOf(shareName, StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                return this[index];
            }
            else
            {
                return null;
            }
        }
    }
}