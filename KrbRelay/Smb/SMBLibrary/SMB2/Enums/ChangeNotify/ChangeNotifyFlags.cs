using System;

namespace SMBLibrary.SMB2
{
    [Flags]
    public enum ChangeNotifyFlags : ushort
    {
        WatchTree = 0x0001, // SMB2_WATCH_TREE
    }
}