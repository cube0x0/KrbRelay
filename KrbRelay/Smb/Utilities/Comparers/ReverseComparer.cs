/* Copyright (C) 2005-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;

namespace Utilities
{
    public class ReverseComparer<T> : IComparer<T>
    {
        private IComparer<T> m_comparer;

        public ReverseComparer(IComparer<T> comparer)
        {
            m_comparer = comparer;
        }

        public int Compare(T x, T y)
        {
            return m_comparer.Compare(y, x);
        }
    }
}