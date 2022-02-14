namespace SMBLibrary
{
    public enum FileSystemControlFlags : uint
    {
        QuotaTrack = 0x00000001,              // FILE_VC_QUOTA_TRACK
        QuotaEnforce = 0x00000002,            // FILE_VC_QUOTA_ENFORCE
        ContentIndexingDisabled = 0x00000008, // FILE_VC_CONTENT_INDEX_DISABLED
        LogQuotaThreshold = 0x00000010,       // FILE_VC_LOG_QUOTA_THRESHOLD
        LogQuotaLimit = 0x00000020,           // FILE_VC_LOG_QUOTA_LIMIT
        LogVolumeThreshold = 0x00000040,      // FILE_VC_LOG_VOLUME_THRESHOLD
        LogVolumeLimit = 0x00000080,          // FILE_VC_LOG_VOLUME_LIMIT
        QuotasIncomplete = 0x00000100,        // FILE_VC_QUOTAS_INCOMPLETE
        QuotasRebuilding = 0x00000200,        // FILE_VC_QUOTAS_REBUILDING
    }
}