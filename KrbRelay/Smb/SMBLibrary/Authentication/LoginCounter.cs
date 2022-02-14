/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;

namespace SMBLibrary.Authentication
{
    public class LoginCounter
    {
        public class LoginEntry
        {
            public DateTime LoginWindowStartDT;
            public int NumberOfAttempts;
        }

        private int m_maxLoginAttemptsInWindow;
        private TimeSpan m_loginWindowDuration;
        private Dictionary<string, LoginEntry> m_loginEntries = new Dictionary<string, LoginEntry>();

        public LoginCounter(int maxLoginAttemptsInWindow, TimeSpan loginWindowDuration)
        {
            m_maxLoginAttemptsInWindow = maxLoginAttemptsInWindow;
            m_loginWindowDuration = loginWindowDuration;
        }

        public bool HasRemainingLoginAttempts(string userID)
        {
            return HasRemainingLoginAttempts(userID, false);
        }

        public bool HasRemainingLoginAttempts(string userID, bool incrementCount)
        {
            lock (m_loginEntries)
            {
                LoginEntry entry;
                if (m_loginEntries.TryGetValue(userID, out entry))
                {
                    if (entry.LoginWindowStartDT.Add(m_loginWindowDuration) >= DateTime.UtcNow)
                    {
                        // Existing login Window
                        if (incrementCount)
                        {
                            entry.NumberOfAttempts++;
                        }
                    }
                    else
                    {
                        // New login Window
                        if (!incrementCount)
                        {
                            return true;
                        }
                        entry.LoginWindowStartDT = DateTime.UtcNow;
                        entry.NumberOfAttempts = 1;
                    }
                }
                else
                {
                    if (!incrementCount)
                    {
                        return true;
                    }
                    entry = new LoginEntry();
                    entry.LoginWindowStartDT = DateTime.UtcNow;
                    entry.NumberOfAttempts = 1;
                    m_loginEntries.Add(userID, entry);
                }
                return (entry.NumberOfAttempts < m_maxLoginAttemptsInWindow);
            }
        }
    }
}