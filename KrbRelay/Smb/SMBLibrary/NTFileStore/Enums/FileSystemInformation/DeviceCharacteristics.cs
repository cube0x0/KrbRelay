using System;

namespace SMBLibrary
{
    [Flags]
    public enum DeviceCharacteristics : uint
    {
        RemovableMedia = 0x0001, // FILE_REMOVABLE_MEDIA
        ReadOnlyDevice = 0x0002, // FILE_READ_ONLY_DEVICE
        FloppyDiskette = 0x0004, // FILE_FLOPPY_DISKETTE
        WriteOnceMedia = 0x0008, // FILE_WRITE_ONCE_MEDIA
        RemoteDevice = 0x0010,   // FILE_REMOTE_DEVICE
        IsMounted = 0x0020,      // FILE_DEVICE_IS_MOUNTED
        VirtualVolume = 0x0040,  // FILE_VIRTUAL_VOLUME
    }
}