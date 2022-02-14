/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;
using System;

namespace SMBLibrary.Services
{
    public class NDRTimeOfDayInfo : INDRStructure
    {
        public uint tod_elapsedt;
        public uint tod_msecs;
        public uint tod_hours;
        public uint tod_mins;
        public uint tod_secs;
        public uint tod_hunds;
        public uint tod_timezone;
        public uint tod_tinterval;
        public uint tod_day;
        public uint tod_month;
        public uint tod_year;
        public uint tod_weekday;

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();

            tod_elapsedt = parser.ReadUInt32();
            tod_msecs = parser.ReadUInt32();
            tod_hours = parser.ReadUInt32();
            tod_mins = parser.ReadUInt32();
            tod_secs = parser.ReadUInt32();
            tod_hunds = parser.ReadUInt32();
            tod_timezone = parser.ReadUInt32();
            tod_tinterval = parser.ReadUInt32();
            tod_day = parser.ReadUInt32();
            tod_month = parser.ReadUInt32();
            tod_year = parser.ReadUInt32();
            tod_weekday = parser.ReadUInt32();
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            throw new NotImplementedException();
        }

        public DateTime ToDateTime()
        {
            var date = new DateTime((int)tod_year, (int)tod_month, (int)tod_day, (int)tod_hours, (int)tod_mins, (int)tod_secs, (int)0, DateTimeKind.Utc);
            return date;
        }
    }
}