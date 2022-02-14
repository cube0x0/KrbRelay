/* Copyright (C) 2005-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace Utilities
{
    public partial class Conversion
    {
        public static short ToInt16(object obj)
        {
            return ToInt16(obj, 0);
        }

        public static short ToInt16(object obj, short defaultValue)
        {
            short result = defaultValue;
            if (obj != null)
            {
                try
                {
                    result = Convert.ToInt16(obj);
                }
                catch
                { }
            }
            return result;
        }

        public static int ToInt32(object obj)
        {
            return ToInt32(obj, 0);
        }

        public static int ToInt32(object obj, int defaultValue)
        {
            int result = defaultValue;
            if (obj != null)
            {
                try
                {
                    result = Convert.ToInt32(obj);
                }
                catch
                { }
            }
            return result;
        }

        public static long ToInt64(object obj)
        {
            return ToInt64(obj, 0);
        }

        public static long ToInt64(object obj, long defaultValue)
        {
            long result = defaultValue;
            if (obj != null)
            {
                try
                {
                    result = Convert.ToInt64(obj);
                }
                catch
                { }
            }
            return result;
        }

        public static ushort ToUInt16(object obj)
        {
            return ToUInt16(obj, 0);
        }

        public static ushort ToUInt16(object obj, ushort defaultValue)
        {
            ushort result = defaultValue;
            if (obj != null)
            {
                try
                {
                    result = Convert.ToUInt16(obj);
                }
                catch
                { }
            }
            return result;
        }

        public static uint ToUInt32(object obj)
        {
            return ToUInt32(obj, 0);
        }

        public static uint ToUInt32(object obj, uint defaultValue)
        {
            uint result = defaultValue;
            if (obj != null)
            {
                try
                {
                    result = Convert.ToUInt32(obj);
                }
                catch
                { }
            }
            return result;
        }

        public static ulong ToUInt64(object obj)
        {
            return ToUInt64(obj, 0);
        }

        public static ulong ToUInt64(object obj, ulong defaultValue)
        {
            ulong result = defaultValue;
            if (obj != null)
            {
                try
                {
                    result = Convert.ToUInt64(obj);
                }
                catch
                { }
            }
            return result;
        }

        public static float ToFloat(object obj)
        {
            return ToFloat(obj, 0);
        }

        public static float ToFloat(object obj, float defaultValue)
        {
            float result = defaultValue;
            if (obj != null)
            {
                try
                {
                    result = Convert.ToSingle(obj);
                }
                catch
                { }
            }
            return result;
        }

        public static double ToDouble(object obj)
        {
            return ToDouble(obj, 0);
        }

        public static double ToDouble(object obj, double defaultValue)
        {
            double result = defaultValue;
            if (obj != null)
            {
                try
                {
                    result = Convert.ToDouble(obj);
                }
                catch
                { }
            }
            return result;
        }

        public static decimal ToDecimal(object obj)
        {
            return ToDecimal(obj, 0);
        }

        public static decimal ToDecimal(object obj, decimal defaultValue)
        {
            decimal result = defaultValue;
            if (obj != null)
            {
                try
                {
                    result = Convert.ToDecimal(obj);
                }
                catch
                { }
            }
            return result;
        }

        public static bool ToBoolean(object obj)
        {
            return ToBoolean(obj, false);
        }

        public static bool ToBoolean(object obj, bool defaultValue)
        {
            bool result = defaultValue;
            if (obj != null)
            {
                try
                {
                    result = Convert.ToBoolean(obj);
                }
                catch
                { }
            }
            return result;
        }

        public static string ToString(object obj)
        {
            string result = String.Empty;
            if (obj != null)
            {
                try
                {
                    result = Convert.ToString(obj);
                }
                catch
                { }
            }
            return result;
        }

        public static char ToChar(object obj)
        {
            return ToChar(obj, new char());
        }

        public static char ToChar(object obj, char defaultValue)
        {
            char result = defaultValue;
            if (obj != null)
            {
                try
                {
                    result = Convert.ToChar(obj);
                }
                catch
                { }
            }
            return result;
        }

        public static DateTime ToDateTime(object obj)
        {
            return ToDateTime(obj, DateTime.MinValue);
        }

        public static DateTime ToDateTime(object obj, DateTime defaultValue)
        {
            DateTime result = defaultValue;
            if (obj != null)
            {
                try
                {
                    result = Convert.ToDateTime(obj);
                }
                catch
                { }
            }
            return result;
        }
    }
}