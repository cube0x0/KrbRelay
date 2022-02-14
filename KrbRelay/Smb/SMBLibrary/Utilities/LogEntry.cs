/* Copyright (C) 2012-2016 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace Utilities
{
    public enum Severity
    {
        Critical = 1,
        Error = 2,
        Warning = 3,
        Information = 4,
        Verbose = 5,
        Debug = 6,
        Trace = 7,
    }

    public class LogEntry : EventArgs
    {
        public DateTime Time;
        public Severity Severity;
        public string Source;
        public string Message;

        public LogEntry(DateTime time, Severity severity, string source, string message)
        {
            Time = time;
            Severity = severity;
            Source = source;
            Message = message;
        }
    }
}