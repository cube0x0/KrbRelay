/* Copyright (C) 2012-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using System.ComponentModel;

namespace Utilities
{
    public partial class KeyValuePairList<TKey, TValue>
    {
        public new void Sort()
        {
            this.Sort(Comparer<TKey>.Default);
        }

        public void Sort(ListSortDirection sortDirection)
        {
            Sort(Comparer<TKey>.Default, sortDirection);
        }

        public void Sort(IComparer<TKey> comparer, ListSortDirection sortDirection)
        {
            if (sortDirection == ListSortDirection.Ascending)
            {
                Sort(comparer);
            }
            else
            {
                Sort(new ReverseComparer<TKey>(comparer));
            }
        }

        public void Sort(IComparer<TKey> comparer)
        {
            this.Sort(delegate (KeyValuePair<TKey, TValue> a, KeyValuePair<TKey, TValue> b)
            {
                return comparer.Compare(a.Key, b.Key);
            });
        }
    }
}