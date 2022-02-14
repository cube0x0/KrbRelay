/* Copyright (C) 2017-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace Utilities
{
    public class Reference<T> where T : struct
    {
        private T m_value;

        public Reference(T value)
        {
            m_value = value;
        }

        public T Value
        {
            get { return m_value; }
            set { m_value = value; }
        }

        public override string ToString()
        {
            return m_value.ToString();
        }

        public static implicit operator T(Reference<T> wrapper)
        {
            return wrapper.Value;
        }

        public static implicit operator Reference<T>(T value)
        {
            return new Reference<T>(value);
        }
    }
}