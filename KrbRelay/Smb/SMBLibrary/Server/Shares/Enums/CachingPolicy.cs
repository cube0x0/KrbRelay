namespace SMBLibrary.Server
{
    /// <summary>
    /// Client-Side Caching Policy
    /// </summary>
    public enum CachingPolicy
    {
        /// <summary>
        /// The client can cache files that are explicitly selected by the user for offline use.
        /// Automatic file-by-file reintegration is not allowed.
        /// </summary>
        ManualCaching,

        /// <summary>
        /// The client can automatically cache files that are used by the user for offline access.
        /// Automatic file-by-file reintegration is allowed.
        /// </summary>
        AutoCaching,

        /// <summary>
        /// The client can automatically cache files that are used by the user for offline access.
        /// Clients are permitted to work from their local cache even while online.
        /// </summary>
        VideoCaching,

        /// <summary>
        /// No offline caching is allowed for this share.
        /// </summary>
        NoCaching,
    }
}