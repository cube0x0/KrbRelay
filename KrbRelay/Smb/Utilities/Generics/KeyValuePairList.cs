/* Copyright (C) 2012-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;

namespace Utilities
{
    public partial class KeyValuePairList<TKey, TValue> : List<KeyValuePair<TKey, TValue>>
    {
        public KeyValuePairList()
        {
        }

        public KeyValuePairList(List<KeyValuePair<TKey, TValue>> collection) : base(collection)
        {
        }

        public bool ContainsKey(TKey key)
        {
            return (this.IndexOfKey(key) != -1);
        }

        public int IndexOfKey(TKey key)
        {
            for (int index = 0; index < this.Count; index++)
            {
                if (this[index].Key.Equals(key))
                {
                    return index;
                }
            }

            return -1;
        }

        public TValue ValueOf(TKey key)
        {
            for (int index = 0; index < this.Count; index++)
            {
                if (this[index].Key.Equals(key))
                {
                    return this[index].Value;
                }
            }

            return default(TValue);
        }

        public void Add(TKey key, TValue value)
        {
            this.Add(new KeyValuePair<TKey, TValue>(key, value));
        }

        public List<TKey> Keys
        {
            get
            {
                List<TKey> result = new List<TKey>();
                foreach (KeyValuePair<TKey, TValue> entity in this)
                {
                    result.Add(entity.Key);
                }
                return result;
            }
        }

        public List<TValue> Values
        {
            get
            {
                List<TValue> result = new List<TValue>();
                foreach (KeyValuePair<TKey, TValue> entity in this)
                {
                    result.Add(entity.Value);
                }
                return result;
            }
        }

        public new KeyValuePairList<TKey, TValue> GetRange(int index, int count)
        {
            return new KeyValuePairList<TKey, TValue>(base.GetRange(index, count));
        }
    }
}