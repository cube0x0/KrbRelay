using SMBLibrary.Client.Helpers;
using SMBLibrary.Services;

namespace SMBLibrary.Client
{
    public class TschServiceHelper
    {
        public static schRpcRegisterTaskResponse schRpcRegisterTask(RPCCallHelper rpc, out NTStatus status)
        {
            schRpcRegisterTaskRequest schRpcRegisterTaskRequest = new schRpcRegisterTaskRequest();
            schRpcRegisterTaskRequest.path = null;
            schRpcRegisterTaskRequest.xml = @"
<?xml version=""1.0"" encoding =""UTF-16"" ?>
<Task version=""1.2"" xmlns =""http://schemas.microsoft.com/windows/2004/02/mit/task"" >
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id=""LocalSystem"" >
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context=""LocalSystem"" >
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>";
            schRpcRegisterTaskRequest.flags = TASK_CREATION.TASK_CREATE;
            schRpcRegisterTaskRequest.sddl = null;
            schRpcRegisterTaskRequest.logonType = TASK_LOGON_TYPE.TASK_LOGON_NONE;
            schRpcRegisterTaskRequest.cCreds = 0;
            schRpcRegisterTaskRequest.pCreds = new TASK_USER_CRED();
            schRpcRegisterTaskRequest.pCreds.userId = null;
            schRpcRegisterTaskRequest.pCreds.password = null;

            schRpcRegisterTaskResponse schRpcRegisterTaskResponse;

            status = rpc.ExecuteCall((ushort)TschServiceOpName.SchRpcRegisterTask, schRpcRegisterTaskRequest, out schRpcRegisterTaskResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return schRpcRegisterTaskResponse;
        }
    }
}