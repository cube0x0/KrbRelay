using System;

namespace SMBLibrary
{
    [Flags]
    public enum SectorSizeInformationFlags : uint
    {
        AlignedDevice = 0x00000001,            // SSINFO_FLAGS_ALIGNED_DEVICE
        PartitionAlignedOnDevice = 0x00000002, // SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE
        NoSeekPenalty = 0x0000004,             // SSINFO_FLAGS_NO_SEEK_PENALTY
        TrimEnabled = 0x00000008,              // SSINFO_FLAGS_TRIM_ENABLED
    }
}