namespace SMBLibrary
{
    public enum DeviceType : uint
    {
        Beep = 0x0001,              // FILE_DEVICE_BEEP
        CDRom = 0x0002,             // FILE_DEVICE_CD_ROM
        CDRomFileSystem = 0x0003,   // FILE_DEVICE_CD_ROM_FILE_SYSTEM
        Controller = 0x0004,        // FILE_DEVICE_CONTROLLER
        DataLink = 0x0005,          // FILE_DEVICE_DATALINK
        DFS = 0x0006,               // FILE_DEVICE_DFS
        Disk = 0x0007,              // FILE_DEVICE_DISK
        DiskFileSystem = 0x0008,    // FILE_DEVICE_DISK_FILE_SYSTEM
        FileSystem = 0x0009,        // FILE_DEVICE_FILE_SYSTEM
        ImportPort = 0x000A,        // FILE_DEVICE_INPORT_PORT
        Keyboard = 0x000B,          // FILE_DEVICE_KEYBOARD
        MailSlot = 0x000C,          // FILE_DEVICE_MAILSLOT
        MidiIn = 0x000D,            // FILE_DEVICE_MIDI_IN
        MidiOut = 0x000E,           // FILE_DEVICE_MIDI_OUT
        Mouse = 0x000F,             // FILE_DEVICE_MOUSE
        MultiUNCProvider = 0x0010,  // FILE_DEVICE_MULTI_UNC_PROVIDER
        NamedPipe = 0x0011,         // FILE_DEVICE_NAMED_PIPE
        Network = 0x0012,           // FILE_DEVICE_NETWORK
        NetworkBrowser = 0x0013,    // FILE_DEVICE_NETWORK_BROWSER
        NetworkFileSystem = 0x0014, // FILE_DEVICE_NETWORK_FILE_SYSTEM
        Null = 0x0015,              // FILE_DEVICE_NULL
        ParallelPort = 0x0016,      // FILE_DEVICE_PARALLEL_PORT
        PhysicalNetcard = 0x0017,   // FILE_DEVICE_PHYSICAL_NETCARD
        Printer = 0x0018,           // FILE_DEVICE_PRINTER
        Scanner = 0x0019,           // FILE_DEVICE_SCANNER
        SerialMousePort = 0x001A,   // FILE_DEVICE_SERIAL_MOUSE_PORT
        SerialPort = 0x001B,        // FILE_DEVICE_SERIAL_PORT
        Screen = 0x001C,            // FILE_DEVICE_SCREEN
        Sound = 0x001D,             // FILE_DEVICE_SOUND
        Streams = 0x001E,           // FILE_DEVICE_STREAMS
        Tape = 0x001F,              // FILE_DEVICE_TAPE
        TapeFileSystem = 0x0020,    // FILE_DEVICE_TAPE_FILE_SYSTEM
        Transport = 0x0021,         // FILE_DEVICE_TRANSPORT
        Unknown = 0x0022,           // FILE_DEVICE_UNKNOWN
        Video = 0x0023,             // FILE_DEVICE_VIDEO
        VirtualDisk = 0x0024,       // FILE_DEVICE_VIRTUAL_DISK
        WaveIn = 0x0025,            // FILE_DEVICE_WAVE_IN
        WaveOut = 0x0026,           // FILE_DEVICE_WAVE_OUT
        PS2Port = 0x0027,           // FILE_DEVICE_8042_PORT
        NetworkRedirector = 0x0028, // FILE_DEVICE_NETWORK_REDIRECTOR
        Battery = 0x0029,           // FILE_DEVICE_BATTERY
        BusExtender = 0x002A,       // FILE_DEVICE_BUS_EXTENDER
        Modem = 0x002B,             // FILE_DEVICE_MODEM
        VirtualDosMachine = 0x002C, // FILE_DEVICE_VDM
    }
}