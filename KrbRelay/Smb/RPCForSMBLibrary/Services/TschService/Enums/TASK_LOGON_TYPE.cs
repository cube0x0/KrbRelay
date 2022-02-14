namespace SMBLibrary.Services
{
    public enum TASK_LOGON_TYPE : ushort
    {
        TASK_LOGON_NONE = 0,
        TASK_LOGON_PASSWORD = 1,
        TASK_LOGON_S4U = 2,
        TASK_LOGON_INTERACTIVE_TOKEN = 3,
        TASK_LOGON_GROUP = 4,
        TASK_LOGON_SERVICE_ACCOUNT = 5,
        TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD = 6
    }
}