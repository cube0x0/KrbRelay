/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * Based on:
 * http://coding-time.blogspot.pt/2008/03/implement-your-own-parallelfor-in-c.html
 * C# 2.0 adaptation based on:
 * http://dotnetgalactics.wordpress.com/2009/11/19/how-to-provide-a-parallel-for-loop-in-c2-0-2/
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace Utilities
{
    public delegate void ForDelegate(int i);

    public delegate void DelegateProcess();

    public class Parallel
    {
        /// <summary>
        /// Parallel for loop. Invokes given action, passing arguments
        /// fromInclusive - toExclusive on multiple threads.
        /// Returns when loop finished.
        /// </summary>
        public static void For(int fromInclusive, int toExclusive, ForDelegate forDelegate)
        {
            int chunkSize = 4;
            For(fromInclusive, toExclusive, chunkSize, forDelegate);
        }

        /// <summary>
        /// Parallel for loop. Invokes given action, passing arguments
        /// fromInclusive - toExclusive on multiple threads.
        /// Returns when loop finished.
        /// </summary>
        /// <param name="chunkSize">
        /// chunkSize = 1 makes items to be processed in order.
        /// Bigger chunk size should reduce lock waiting time and thus
        /// increase paralelism.
        /// </param>
        public static void For(int fromInclusive, int toExclusive, int chunkSize, ForDelegate forDelegate)
        {
            int threadCount = Environment.ProcessorCount;
            For(fromInclusive, toExclusive, chunkSize, threadCount, forDelegate);
        }

        /// <summary>
        /// Parallel for loop. Invokes given action, passing arguments
        /// fromInclusive - toExclusive on multiple threads.
        /// Returns when loop finished.
        /// </summary>
        /// <param name="chunkSize">
        /// chunkSize = 1 makes items to be processed in order.
        /// Bigger chunk size should reduce lock waiting time and thus
        /// increase paralelism.
        /// </param>
        /// <param name="threadCount">number of process() threads</param>
        public static void For(int fromInclusive, int toExclusive, int chunkSize, int threadCount, ForDelegate forDelegate)
        {
            int index = fromInclusive - chunkSize;
            // locker object shared by all the process() delegates
            object locker = new object();

            // processing function
            // takes next chunk and processes it using action
            DelegateProcess process = delegate ()
            {
                while (true)
                {
                    int chunkStart = 0;
                    lock (locker)
                    {
                        // take next chunk
                        index += chunkSize;
                        chunkStart = index;
                    }
                    // process the chunk
                    // (another thread is processing another chunk
                    //  so the real order of items will be out-of-order)
                    for (int i = chunkStart; i < chunkStart + chunkSize; i++)
                    {
                        if (i >= toExclusive) return;
                        forDelegate(i);
                    }
                }
            };

            // launch process() threads
            IAsyncResult[] asyncResults = new IAsyncResult[threadCount];
            for (int i = 0; i < threadCount; ++i)
            {
                asyncResults[i] = process.BeginInvoke(null, null);
            }
            // wait for all threads to complete
            for (int i = 0; i < threadCount; ++i)
            {
                process.EndInvoke(asyncResults[i]);
            }
        }
    }
}