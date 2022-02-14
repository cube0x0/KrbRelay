/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * Based on:
 * http://stackoverflow.com/questions/10966331/two-way-bidirectional-dictionary-in-c
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;

namespace Utilities
{
    public class Map<T1, T2>
    {
        private Dictionary<T1, T2> m_forward = new Dictionary<T1, T2>();
        private Dictionary<T2, T1> m_reverse = new Dictionary<T2, T1>();

        public Map()
        {
            m_forward = new Dictionary<T1, T2>();
            m_reverse = new Dictionary<T2, T1>();
        }

        public void Add(T1 key, T2 value)
        {
            m_forward.Add(key, value);
            m_reverse.Add(value, key);
        }

        public bool ContainsKey(T1 key)
        {
            return m_forward.ContainsKey(key);
        }

        public bool ContainsValue(T2 value)
        {
            return m_reverse.ContainsKey(value);
        }

        public bool TryGetKey(T2 value, out T1 key)
        {
            return m_reverse.TryGetValue(value, out key);
        }

        public bool TryGetValue(T1 key, out T2 value)
        {
            return m_forward.TryGetValue(key, out value);
        }

        public void RemoveKey(T1 key)
        {
            T2 value;
            if (m_forward.TryGetValue(key, out value))
            {
                m_forward.Remove(key);
                m_reverse.Remove(value);
            }
        }

        public void RemoveValue(T2 value)
        {
            T1 key;
            if (m_reverse.TryGetValue(value, out key))
            {
                m_forward.Remove(key);
                m_reverse.Remove(value);
            }
        }

        public T2 this[T1 key]
        {
            get
            {
                return m_forward[key];
            }
        }

        public T1 GetKey(T2 value)
        {
            return m_reverse[value];
        }
    }
}