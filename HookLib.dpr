library HookLib;

{$SETPEFLAGS $0002 or $0004 or $0008 or $0010 or $0020 or $0200 or $0400 or $0800 or $1000}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}

uses
  Windows,
  TlHelp32,
  HookAPI in 'HookAPI.pas',
  MappingAPI in 'MappingAPI.pas',
  MicroDAsm in 'MicroDAsm.pas';

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH


type
  UNICODE_STRING = record
    Length        : Word;
    MaximumLength : Word;
    Buffer        : Pointer;
  end;

  UNICODE_STRING64 = record
    Length        : Word;
    MaximumLength : Word;
    Fill          : LongWord;
    Buffer        : Pointer;
  end;


  SYSTEM_PROCESS_INFORMATION32 = record
    NextEntryOffset              : ULONG;
    NumberOfThreads              : ULONG;
    WorkingSetPrivateSize        : LARGE_INTEGER;
    HardFaultCount               : ULONG;
    NumberOfThreadsHighWatermark : ULONG;
    CycleTime                    : ULONGLONG;
    CreateTime                   : LARGE_INTEGER;
    UserTime                     : LARGE_INTEGER;
    KernelTime                   : LARGE_INTEGER;
    ImageName                    : UNICODE_STRING;
    BasePriority                 : LONG;
    UniqueProcessId              : ULONG;
    InheritedFromUniqueProcessId : ULONG;
    HandleCount                  : ULONG;
    SessionId                    : ULONG;
    UniqueProcessKey             : ULONG_PTR;
    PeakVirtualSize              : SIZE_T;
    VirtualSize                  : SIZE_T;
    PageFaultCount               : ULONG;
    PeakWorkingSetSize           : SIZE_T;
    WorkingSetSize               : SIZE_T;
    QuotaPeakPagedPoolUsage      : SIZE_T;
    QuotaPagedPoolUsage          : SIZE_T;
    QuotaPeakNonPagedPoolUsage   : SIZE_T;
    QuotaNonPagedPoolUsage       : SIZE_T;
    PagefileUsage                : SIZE_T;
    PeakPagefileUsage            : SIZE_T;
    PrivatePageCount             : SIZE_T;
    ReadOperationCount           : LARGE_INTEGER;
    WriteOperationCount          : LARGE_INTEGER;
    OtherOperationCount          : LARGE_INTEGER;
    ReadTransferCount            : LARGE_INTEGER;
    WriteTransferCount           : LARGE_INTEGER;
    OtherTransferCount           : LARGE_INTEGER;
  end;

  SYSTEM_PROCESS_INFORMATION64 = record
    NextEntryOffset              : ULONG;
    NumberOfThreads              : ULONG;
    WorkingSetPrivateSize        : LARGE_INTEGER;
    HardFaultCount               : ULONG;
    NumberOfThreadsHighWatermark : ULONG;
    CycleTime                    : ULONGLONG;
    CreateTime                   : LARGE_INTEGER;
    UserTime                     : LARGE_INTEGER;
    KernelTime                   : LARGE_INTEGER;
    ImageName                    : UNICODE_STRING64;
    BasePriority                 : UINT64;
    UniqueProcessID              : UINT64;
    InheritedFromUniqueProcessId : UINT64;
    HandleCount                  : UINT64;
    SessionId                    : UINT64;
    UniqueProcessKey             : UINT64;
    PeakVirtualSize              : UINT64;
    VirtualSize                  : UINT64;
    PageFaultCount               : UINT64;
    PeakWorkingSetSize           : UINT64;
    WorkingSetSize               : UINT64;
    QuotaPeakPagedPoolUsage      : UINT64;
    QuotaPagedPoolUsage          : UINT64;
    QuotaPeakNonPagedPoolUsage   : UINT64;
    QuotaNonPagedPoolUsage       : UINT64;
    PagefileUsage                : UINT64;
    PeakPagefileUsage            : UINT64;
    PrivatePageCount             : UINT64;
    ReadOperationCount           : LARGE_INTEGER;
    WriteOperationCount          : LARGE_INTEGER;
    OtherOperationCount          : LARGE_INTEGER;
    ReadTransferCount            : LARGE_INTEGER;
    WriteTransferCount           : LARGE_INTEGER;
    OtherTransferCount           : LARGE_INTEGER;
  end;


  SYSTEM_INFORMATION_CLASS = (
                               SystemBasicInformation,
                               SystemProcessorInformation,
                               SystemPerformanceInformation,
                               SystemTimeOfDayInformation,
                               SystemPathInformation,
                               SystemProcessInformation,
                               SystemCallCountInformation,
                               SystemDeviceInformation,
                               SystemProcessorPerformanceInformation,
                               SystemFlagsInformation,
                               SystemCallTimeInformation,
                               SystemModuleInformation,
                               SystemLocksInformation,
                               SystemStackTraceInformation,
                               SystemPagedPoolInformation,
                               SystemNonPagedPoolInformation,
                               SystemHandleInformation,
                               SystemObjectInformation,
                               SystemPageFileInformation,
                               SystemVdmInstemulInformation,
                               SystemVdmBopInformation,
                               SystemFileCacheInformation,
                               SystemPoolTagInformation,
                               SystemInterruptInformation,
                               SystemDpcBehaviorInformation,
                               SystemFullMemoryInformation,
                               SystemLoadGdiDriverInformation,
                               SystemUnloadGdiDriverInformation,
                               SystemTimeAdjustmentInformation,
                               SystemSummaryMemoryInformation,
                               SystemMirrorMemoryInformation,
                               SystemPerformanceTraceInformation,
                               SystemObsolete0,
                               SystemExceptionInformation,
                               SystemCrashDumpStateInformation,
                               SystemKernelDebuggerInformation
                              );

  NTSTATUS = LongWord;

  {$IFDEF CPUX64}
    SYSTEM_PROCESS_INFORMATION = SYSTEM_PROCESS_INFORMATION64;
    PSYSTEM_PROCESS_INFORMATION = ^SYSTEM_PROCESS_INFORMATION64;
  {$ELSE}
    SYSTEM_PROCESS_INFORMATION = SYSTEM_PROCESS_INFORMATION32;
    PSYSTEM_PROCESS_INFORMATION = ^SYSTEM_PROCESS_INFORMATION32;
  {$ENDIF}


//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

var
  TrueNtQuerySystemInformation: function(
                                          SystemInformationClass: LongWord;
                                          SystemInformation: Pointer;
                                          SystemInformationLength: ULONG;
                                          ReturnLength: PULONG
                                         ): NTSTATUS; stdcall;

  NtQuerySystemInformation: Pointer;
  GlobalHookHandle: THandle = 0;
  HookingState: Boolean = False;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


// Функция, которая будет выполнена вместо перехваченной NtQuerySystemInformation:
function HookedNtQuerySystemInformation(
                                         SystemInformationClass: LongWord;
                                         SystemInformation: PSYSTEM_PROCESS_INFORMATION;
                                         SystemInformationLength: ULONG;
                                         ReturnLength: PULONG
                                        ): NTSTATUS; stdcall;
var
  MappedFilePointer: Pointer;
  HidingProcessID: LongWord;
  SystemInfo: PSYSTEM_PROCESS_INFORMATION;
begin
  Result := TrueNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

  // Проверяем случаи, когда изменять результат не надо::
  if HookingState or (Result <> 0) then Exit;
  if SystemInformationClass <> LongWord(SystemProcessInformation) then Exit;

  MappedFilePointer := GetMappedMemory('HookAPI Map', SizeOf(HidingProcessID));

  if MappedFilePointer = nil then Exit;

  HidingProcessID := LongWord(MappedFilePointer^);
  if HidingProcessID = $FFFFFFFF then
  begin
    FreeMappedMemory(MappedFilePointer);
    Exit;
  end;

  SystemInfo := SystemInformation;

  while SystemInfo.NextEntryOffset > 0 do
  begin
    // Если следующий элемент - наш процесс,...:
    if PSYSTEM_PROCESS_INFORMATION(NativeUInt(SystemInfo) + SystemInfo.NextEntryOffset).UniqueProcessId = HidingProcessID then
    begin
      // ...то скрываем его:
      if PSYSTEM_PROCESS_INFORMATION(NativeUInt(SystemInfo) + SystemInfo.NextEntryOffset).NextEntryOffset <> 0 then
        SystemInfo.NextEntryOffset := PSYSTEM_PROCESS_INFORMATION(NativeUInt(SystemInfo) + SystemInfo.NextEntryOffset).NextEntryOffset + SystemInfo.NextEntryOffset
      else
        SystemInfo.NextEntryOffset := 0;

      Break;
    end;

    SystemInfo := Pointer(NativeUInt(SystemInfo) + SystemInfo.NextEntryOffset);
  end;

  FreeMappedMemory(MappedFilePointer);
end;


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


procedure HideProcess(ProcessID: LongWord; HideInAllProcesses: Boolean); stdcall; export;
var
  MappedMemory: Pointer;
begin
  MappedMemory := GetMappedMemory('HookAPI Map', SizeOf(ProcessID));
  if MappedMemory <> nil then
  begin
    LongWord(MappedMemory^) := ProcessID;
    FreeMappedMemory(MappedMemory);
  end;

  if (HideInAllProcesses) and (GlobalHookHandle = 0) then HookEmAll(GlobalHookHandle);
end;


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


procedure UnHideProcess; stdcall; export;
begin
  HookingState := True;
  UnHook(NtQuerySystemInformation, @TrueNtQuerySystemInformation);
  HookingState := False;

  if GlobalHookHandle <> 0 then UnHookEmAll(GlobalHookHandle);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


procedure DLLMain(dwReason: LongWord);
begin
   case dwReason of
    DLL_PROCESS_ATTACH:
    begin
      NtSetPrivilege(SE_DEBUG_NAME, True);
      NtQuerySystemInformation := GetProcAddress(GetModuleHandle('ntdll.dll'), 'NtQuerySystemInformation');

      HookingState := True;
      SetHook(NtQuerySystemInformation, @HookedNtQuerySystemInformation, @TrueNtQuerySystemInformation);
      HookingState := False;
    end;

    DLL_PROCESS_DETACH:
    begin
      HookingState := True;
      UnHook(NtQuerySystemInformation, @TrueNtQuerySystemInformation);
      HookingState := False;

      FreeOriginalBlock(@TrueNtQuerySystemInformation);

      if GlobalHookHandle <> 0 then UnHookEmAll(GlobalHookHandle);
    end;
  end;
end;


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

exports HideProcess;
exports UnHideProcess;

begin
  DllProc := @DLLMain;
  DllProc(DLL_PROCESS_ATTACH);
end.

