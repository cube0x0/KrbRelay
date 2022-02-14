namespace SMBLibrary.Services
{
    public enum TASK_CREATION : ushort
    {
        TASK_VALIDATE_ONLY = 0x1,
        TASK_CREATE = 0x2,
        TASK_UPDATE = 0x4,
        TASK_CREATE_OR_UPDATE,
        TASK_DISABLE = 0x8,
        TASK_DONT_ADD_PRINCIPAL_ACE = 0x10,
        TASK_IGNORE_REGISTRATION_TRIGGERS = 0x20
    }
}