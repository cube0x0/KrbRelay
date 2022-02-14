/* Copyright (C) 2016-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Threading;

namespace Utilities
{
    public class CountdownLatch
    {
        private int m_count;
        private EventWaitHandle m_waitHandle = new EventWaitHandle(true, EventResetMode.ManualReset);

        public CountdownLatch()
        {
        }

        public void Increment()
        {
            int count = Interlocked.Increment(ref m_count);
            if (count == 1)
            {
                m_waitHandle.Reset();
            }
        }

        public void Add(int value)
        {
            int count = Interlocked.Add(ref m_count, value);
            if (count == value)
            {
                m_waitHandle.Reset();
            }
        }

        public void Decrement()
        {
            int count = Interlocked.Decrement(ref m_count);
            if (m_count == 0)
            {
                m_waitHandle.Set();
            }
            else if (count < 0)
            {
                throw new InvalidOperationException("Count must be greater than or equal to 0");
            }
        }

        public void WaitUntilZero()
        {
            m_waitHandle.WaitOne();
        }
    }
}