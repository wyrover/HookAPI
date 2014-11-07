unit HookAPI;

interface

uses
  Windows, TlHelp32, PSAPI;

const
  SE_DEBUG_NAME         = 'SeDebugPrivilege';
  SE_SHUTDOWN_NAME      = 'SeShutdownPrivilege';
  THREAD_SUSPEND_RESUME = $0002;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

{$IFDEF CPUX64}
// Структура для х64:
type
  TFarJump = packed record
    MovRaxCommand: Word;
    MovRaxArgument: Pointer;
    PushRaxCommand: Byte;
    RetCommand: Byte;
  end;

  NativeUInt = UInt64;
{$ELSE}
// Структура для х32:
type
  TFarJump = packed record
    PushOp: Byte;
    PushArg: Pointer;
    RetOp: Byte;
  end;

  NativeUInt = LongWord;
{$ENDIF}

type
  TOriginalBlock = array [0 .. SizeOf(TFarJump) - 1] of Byte;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

// Установка привилегий:
function NTSetPrivilege(sPrivilege: string; bEnabled: Boolean): Boolean;

// Внедрение библиотеки:
function InjectDll32(ProcessID: LongWord; ModulePath: PAnsiChar; LLAddress: LongWord = 0; ETAddress: LongWord = 0): Boolean;
function InjectDll64(ProcessID: LongWord; ModulePath: PAnsiChar; LLAddress: UInt64 = 0; ETAddress: UInt64 = 0): Boolean;

// Выгрузка библиотеки:
function UnloadDll32(ProcessID: LongWord; ModuleName: PAnsiChar; GMHAddress: LongWord = 0; FLAddress: LongWord = 0; ETAddress: LongWord = 0): Boolean;
function UnloadDll64(ProcessID: LongWord; ModuleName: PAnsiChar; GMHAddress: UInt64 = 0; FLAddress: UInt64 = 0; ETAddress: UInt64 = 0): Boolean;

// Для DLL:
procedure StopThreads;
procedure RunThreads;
function  SetHook(OldProcAddress: Pointer; NewProcAddress: Pointer; out OriginalBlock: TOriginalBlock): Boolean;
function  UnHook(OriginalProcAddress: Pointer; OriginalBlock: TOriginalBlock): Boolean;
function  HookEmAll(out GlobalHookHandle: THandle): Boolean;
procedure UnHookEmAll(GlobalHookHandle: THandle);

// Инъекция шелл-кода напрямую:
procedure InjectFunction(ProcessID: LongWord; InjectedFunction: Pointer; InjectedFunctionSize: NativeUInt);

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH


implementation

type
  NTSTATUS = LongWord;

function NtWriteVirtualMemory(
                               hProcess: THandle;
                               BaseAddress: Pointer;
                               Buffer: Pointer;
                               BufferLength: NativeUInt;
                               out ReturnLength: NativeUInt
                              ): NTSTATUS; stdcall; external 'ntdll.dll';


function NtReadVirtualMemory(
                              hProcess: THandle;
                              BaseAddress: Pointer;
                              Buffer: Pointer;
                              BufferSize: NativeUInt;
                              out ReturnLength: NativeUInt
                             ): NTSTATUS; stdcall; external 'ntdll.dll';


function OpenThread(
                     dwDesiredAccess: LongWord;
                     bInheritHandle: LongBool;
                     dwThreadId: LongWord
                    ): LongWord; stdcall; external 'kernel32.dll';


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


// Установка привилегий для работы с чужими процессами:
function NTSetPrivilege(sPrivilege: string; bEnabled: Boolean): Boolean;
var
  hToken: THandle;
  TokenPriv: TOKEN_PRIVILEGES;
  PrevTokenPriv: TOKEN_PRIVILEGES;
  ReturnLength: Cardinal;
begin
  if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, hToken) then
  begin
    if LookupPrivilegeValue(nil, PChar(sPrivilege), TokenPriv.Privileges[0].Luid) then
    begin
      TokenPriv.PrivilegeCount := 1;
      case bEnabled of
        True: TokenPriv.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
        False: TokenPriv.Privileges[0].Attributes := 0;
      end;
      ReturnLength := 0;
      PrevTokenPriv := TokenPriv;
      AdjustTokenPrivileges(hToken, False, TokenPriv, SizeOf(PrevTokenPriv),
      PrevTokenPriv, ReturnLength);
    end;
    CloseHandle(hToken);
  end;
  Result := GetLastError = ERROR_SUCCESS;
end;


(* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Оригинальная функция:
procedure LoadHookLib32;
const
  HookLib: PAnsiChar = 'HookLib.dll';
asm
  push HookLib
  call LoadLibraryA

  xor eax, eax
  push eax
  call ExitThread
end;

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *)

// Инъекция в 32х-битные процессы:
function InjectDll32(ProcessID: LongWord; ModulePath: PAnsiChar; LLAddress: LongWord = 0; ETAddress: LongWord = 0): Boolean;
var
  ProcessHandle: NativeUInt;
  Memory: Pointer;
  Code: LongWord;
  BytesWritten: NativeUInt;
  ThreadId: LongWord;
  hThread: LongWord;
  hKernel32: LongWord;

  // Структура машинного кода инициализации и запуска библиотеки:
  Inject: packed record
    // LL* = LoadLibrary:
    LLPushCommand: Byte;
    LLPushArgument: LongWord;
    LLCallCommand: Word;
    LLCallAddr: LongWord;

    // ET* = ExitThread:
    ETPushCommand: Byte;
    ETPushArgument: LongWord;
    ETCallCommand: Word;
    ETCallAddr: LongWord;

    AddrLoadLibrary: LongWord;
    AddrExitThread: LongWord;
    LibraryName: array [0..MAX_PATH] of AnsiChar;
  end;
begin
  Result := false;

  ProcessHandle := OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
  if ProcessHandle = 0 then Exit;

  // Выделяем память в контексте процесса, куда запишем код вызова библиотеки перехватчика:
  Memory := VirtualAllocEx(ProcessHandle, nil, SizeOf(Inject), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if Memory = nil then Exit;

  Code := LongWord(Memory);
  FillChar(Inject, SizeOf(Inject), #0);

// LoadLibraryA:
  Inject.LLPushCommand  := $68;
  Inject.LLPushArgument := Code + 30;
  Inject.LLCallCommand  := $15FF;
  Inject.LLCallAddr     := Code + 22;

// ExitThread:
  Inject.ETPushCommand  := $68;
  Inject.ETPushArgument := 0;
  Inject.ETCallCommand  := $15FF;
  Inject.ETCallAddr     := Code + 26;

  hKernel32 := GetModuleHandle('kernel32.dll');

  if LLAddress = 0 then
    Inject.AddrLoadLibrary := LongWord(GetProcAddress(hKernel32, 'LoadLibraryA'))
  else
    Inject.AddrLoadLibrary := LLAddress;

  if ETAddress = 0 then
    Inject.AddrExitThread  := LongWord(GetProcAddress(hKernel32, 'ExitThread'))
  else
    Inject.AddrExitThread := ETAddress;

  Move(ModulePath^, Inject.LibraryName, Length(ModulePath));

//  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

  // Записываем машинный код в выделенную память:
  if NtWriteVirtualMemory(ProcessHandle, Memory, @Inject, SizeOf(Inject), BytesWritten) <> 0 then Exit;

  // Выполняем машинный код в отдельном потоке:
  hThread := CreateRemoteThread(ProcessHandle, nil, 0, Memory, nil, 0, ThreadId);

  if hThread = 0 then
  begin
    VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);
    EmptyWorkingSet(ProcessHandle);
    CloseHandle(ProcessHandle);
    Exit;
  end;

  WaitForSingleObject(hThread, INFINITE);
  VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);

  CloseHandle(hThread);
  EmptyWorkingSet(ProcessHandle);
  CloseHandle(ProcessHandle);

  Result := True;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Выгрузка библиотеки из 32х-битных процессов:
function UnloadDll32(ProcessID: LongWord; ModuleName: PAnsiChar; GMHAddress: LongWord = 0; FLAddress: LongWord = 0; ETAddress: LongWord = 0): Boolean;
var
  ProcessHandle: NativeUInt;
  Memory: Pointer;
  Code: LongWord;
  BytesWritten: NativeUInt;
  ThreadId: LongWord;
  hThread: LongWord;
  hKernel32: LongWord;

  // Структура машинного кода инициализации и запуска библиотеки:
  Inject: packed record
    // GMH* = GetModuleHandle:
    GMHPushCommand: Byte;
    GMHPushArgument: LongWord;
    GMHCallCommand: Word;
    GMHCallAddr: LongWord;

    // FL* = FreeLibrary:
    FLPushEax: Byte;
    FLCallCommand: Word;
    FLCallAddr: LongWord;

    // ET* = ExitThread:
    ETPushCommand: Byte;
    ETPushArgument: LongWord;
    ETCallCommand: Word;
    ETCallAddr: LongWord;

    AddrGetModuleHandle: LongWord;
    AddrFreeLibrary: LongWord;
    AddrExitThread: LongWord;
    LibraryName: array [0..MAX_PATH] of AnsiChar;
  end;
begin
  Result := false;

  ProcessHandle := OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
  if ProcessHandle = 0 then Exit;

  // Выделяем память в контексте процесса, куда запишем код вызова библиотеки перехватчика:
  Memory := VirtualAllocEx(ProcessHandle, nil, SizeOf(Inject), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if Memory = nil then Exit;

  Code := LongWord(Memory);
  FillChar(Inject, SizeOf(Inject), #0);

// GetModuleHandleA:
  Inject.GMHPushCommand  := $68;
  Inject.GMHPushArgument := Code + 41;
  Inject.GMHCallCommand  := $15FF;
  Inject.GMHCallAddr     := Code + 29;

// FreeLibrary:
  Inject.FLPushEax     := $50;
  Inject.FLCallCommand := $15FF;
  Inject.FLCallAddr    := Code + 33;

// ExitThread:
  Inject.ETPushCommand  := $68;
  Inject.ETPushArgument := 0;
  Inject.ETCallCommand  := $15FF;
  Inject.ETCallAddr     := Code + 37;

  hKernel32 := GetModuleHandle('kernel32.dll');

  if GMHAddress = 0 then
    Inject.AddrGetModuleHandle := LongWord(GetProcAddress(hKernel32, 'GetModuleHandleA'))
  else
    Inject.AddrGetModuleHandle := GMHAddress;

  if FLAddress = 0 then
    Inject.AddrFreeLibrary := LongWord(GetProcAddress(hKernel32, 'FreeLibrary'))
  else
    Inject.AddrFreeLibrary := FLAddress;

  if ETAddress = 0 then
    Inject.AddrExitThread  := LongWord(GetProcAddress(hKernel32, 'ExitThread'))
  else
    Inject.AddrExitThread := ETAddress;

  Move(ModuleName^, Inject.LibraryName, Length(ModuleName));

//  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

  // Записываем машинный код в выделенную память:
  if NtWriteVirtualMemory(ProcessHandle, Memory, @Inject, SizeOf(Inject), BytesWritten) <> 0 then Exit;

  // Выполняем машинный код в отдельном потоке:
  hThread := CreateRemoteThread(ProcessHandle, nil, 0, Memory, nil, 0, ThreadId);

  if hThread = 0 then
  begin
    VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);
    EmptyWorkingSet(ProcessHandle);
    CloseHandle(ProcessHandle);
    Exit;
  end;

  WaitForSingleObject(hThread, INFINITE);
  VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);

  CloseHandle(hThread);
  EmptyWorkingSet(ProcessHandle);
  CloseHandle(ProcessHandle);

  Result := True;
end;


(* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


{
  Передача параметров в х64-функции:

  RCX - первый параметр
  RDX - второй параметр
  R8 - третий параметр
  R9 - четвёртый параметр

  Остальное через стек в соответствии с соглашением о вызове

  Стек необходимо выравнивать при входе в функцию:

  asm
    push rbp
    sub rsp, $20
    mov rbp, rsp

    ...

    lea rsp, [rbp+$20]
    pop rbp
    ret
  end;
}

// Оригинальная функция:
procedure LoadHookLib64;
const
  HookLib: PAnsiChar = 'HookLib.dll';
asm
  push rbp
  sub rsp, $20
  mov rbp, rsp

  mov rcx, HookLib
  call LoadLibraryA

  mov rcx, $0000000000000000
  call ExitThread

  lea rsp, [rbp+$20]
  pop rbp
  ret
end;

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *)


// Инъекция в 64х-битные процессы:
function InjectDll64(ProcessID: LongWord; ModulePath: PAnsiChar; LLAddress: UInt64 = 0; ETAddress: UInt64 = 0): Boolean;
var
  ProcessHandle: NativeUInt;
  Memory: Pointer;
  Code: UInt64;
  BytesWritten: NativeUInt;
  ThreadId: LongWord;
  hThread: LongWord;
  hKernel32: NativeUInt;

  // Структура машинного кода инициализации и запуска библиотеки:
  Inject: packed record
    AlignStackAtStart: UInt64;

    // LL* = LoadLibrary:
    LLMovRaxCommand: Word;
    LLMovRaxArgument: UInt64;
    LLMovRaxData: array [0..2] of Byte;
    LLMovRcxCommand: Word;
    LLMovRcxArgument: UInt64;
    LLCallRax: array [0..2] of Byte;

    // ET* = ExitThread:
    ETMovRaxCommand: Word;
    ETMovRaxArgument: UInt64;
    ETMovRaxData: array [0..2] of Byte;
    ETMovRcxCommand: Word;
    ETMovRcxArgument: UInt64;
    ETCallRax: array [0..2] of Byte;

    AlignStackAtEnd: UInt64;

    AddrLoadLibrary: UInt64;
    AddrExitThread: UInt64;
    LibraryName: array [0..MAX_PATH] of AnsiChar;
  end;
begin
  Result := false;

  ProcessHandle := OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
  if ProcessHandle = 0 then Exit;

// Выделяем память в контексте процесса, куда запишем код вызова библиотеки перехватчика:
  Memory := VirtualAllocEx(ProcessHandle, nil, SizeOf(Inject), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if Memory = nil then Exit;

  Code := UInt64(Memory);
  FillChar(Inject, SizeOf(Inject), #0);

// Выравниваем 64х-битный стек:
  Inject.AlignStackAtStart := $E5894820EC834855;

{
   + - - - - - - - - - - - +
   |  RAX - адрес функции  |
   |  RCX - параметры      |
   + - - - - - - - - - - - +
}

// LoadLibraryA:
  Inject.LLMovRaxCommand := $B848;
  Inject.LLMovRaxArgument := Code + 68; // Code + смещение до адреса LoadLibraryA

  Inject.LLMovRaxData[0] := $48; //  ---+
  Inject.LLMovRaxData[1] := $8B; //  ---+--->  mov RAX, [RAX]
  Inject.LLMovRaxData[2] := $00; //  ---+

  Inject.LLMovRcxCommand := $B948;
  Inject.LLMovRcxArgument := Code + 84; // Code + смещение до начала пути к библиотеке

  Inject.LLCallRax[0] := $48;
  Inject.LLCallRax[1] := $FF;
  Inject.LLCallRax[2] := $D0;

// ExitThread:
  Inject.ETMovRaxCommand := $B848;
  Inject.ETMovRaxArgument := Code + 76; // Code + смещение до адреса ExitThread

  Inject.ETMovRaxData[0] := $48; //  ---+
  Inject.ETMovRaxData[1] := $8B; //  ---+--->  mov RAX, [RAX]
  Inject.ETMovRaxData[2] := $00; //  ---+

  Inject.ETMovRcxCommand := $B948;
  Inject.ETMovRcxArgument := $0000000000000000; // ExitCode = 0

  Inject.ETCallRax[0] := $48;
  Inject.ETCallRax[1] := $FF;
  Inject.ETCallRax[2] := $D0;

// Выравниваем 64х-битный стек:
  Inject.AlignStackAtEnd := $90C3C35D20658D48;


// Записываем адреса библиотек:
  hKernel32 := LoadLibrary('kernel32.dll');

  if LLAddress = 0 then
    Inject.AddrLoadLibrary := UInt64(GetProcAddress(hKernel32, 'LoadLibraryA'))
  else
    Inject.AddrLoadLibrary := LLAddress;

  if ETAddress = 0 then
    Inject.AddrExitThread  := UInt64(GetProcAddress(hKernel32, 'ExitThread'))
  else
    Inject.AddrExitThread := ETAddress;

  Move(ModulePath^, Inject.LibraryName, Length(ModulePath));

//  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

  // Записываем машинный код в выделенную память:
  if NtWriteVirtualMemory(ProcessHandle, Memory, @Inject, SizeOf(Inject), BytesWritten) <> 0 then Exit;

  // Выполняем машинный код в отдельном потоке:
  hThread := CreateRemoteThread(ProcessHandle, nil, 0, Memory, nil, 0, ThreadId);

  if hThread = 0 then
  begin
    VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);
    EmptyWorkingSet(ProcessHandle);
    CloseHandle(ProcessHandle);
    Exit;
  end;

  WaitForSingleObject(hThread, INFINITE);
  VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);

  CloseHandle(hThread);
  EmptyWorkingSet(ProcessHandle);
  CloseHandle(ProcessHandle);

  Result := True;
end;


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Выгрузка библиотеки из 64х-битных процессов:
function UnloadDll64(ProcessID: LongWord; ModuleName: PAnsiChar; GMHAddress: UInt64 = 0; FLAddress: UInt64 = 0; ETAddress: UInt64 = 0): Boolean;
var
  ProcessHandle: NativeUInt;
  Memory: Pointer;
  Code: UInt64;
  BytesWritten: NativeUInt;
  ThreadId: LongWord;
  hThread: LongWord;
  hKernel32: NativeUInt;

  // Структура машинного кода инициализации и запуска библиотеки:
  Inject: packed record
    AlignStackAtStart: UInt64;            // 8

    // GMH* = GetModuleHandle:
    GMHMovRaxCommand: Word;               // 2
    GMHMovRaxArgument: UInt64;            // 8
    GMHMovRaxData: array [0..2] of Byte;  // 3
    GMHMovRcxCommand: Word;               // 2
    GMHMovRcxArgument: UInt64;            // 8
    GMHCallRax: array [0..2] of Byte;     // 3

    // FL* = FreeLibrary:
    FLMovRcxRax: array [0..2] of Byte;    // 3
    FLMovRaxCommand: Word;                // 2
    FLMovRaxArgument: UInt64;             // 8
    FLMovRaxData: array [0..2] of Byte;   // 3
    FLCallRax: array [0..2] of Byte;      // 3

    // ET* = ExitThread:
    ETMovRaxCommand: Word;                // 2
    ETMovRaxArgument: UInt64;             // 8
    ETMovRaxData: array [0..2] of Byte;   // 3
    ETMovRcxCommand: Word;                // 2
    ETMovRcxArgument: UInt64;             // 8
    ETCallRax: array [0..2] of Byte;      // 3

    AlignStackAtEnd: UInt64;              // 8

    AddrGetModuleHandle: UInt64;          // 8
    AddrFreeLibrary: UInt64;              // 8
    AddrExitThread: UInt64;               // 8
    LibraryName: array [0..MAX_PATH] of AnsiChar;
  end;
begin
  Result := false;

  ProcessHandle := OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
  if ProcessHandle = 0 then Exit;

// Выделяем память в контексте процесса, куда запишем код вызова библиотеки перехватчика:
  Memory := VirtualAllocEx(ProcessHandle, nil, SizeOf(Inject), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if Memory = nil then Exit;

  Code := UInt64(Memory);
  FillChar(Inject, SizeOf(Inject), #0);

// Выравниваем 64х-битный стек:
  Inject.AlignStackAtStart := $E5894820EC834855;

{
   + - - - - - - - - - - - +
   |  RAX - адрес функции  |
   |  RCX - параметры      |
   + - - - - - - - - - - - +
}

// GetModuleHandleA:
  Inject.GMHMovRaxCommand := $B848;
  Inject.GMHMovRaxArgument := Code + 87; // Code + смещение до адреса GetModuleHandleA

  Inject.GMHMovRaxData[0] := $48; //  ---+
  Inject.GMHMovRaxData[1] := $8B; //  ---+--->  mov RAX, [RAX]
  Inject.GMHMovRaxData[2] := $00; //  ---+

  Inject.GMHMovRcxCommand := $B948;
  Inject.GMHMovRcxArgument := Code + 111; // Code + смещение до начала имени библиотеки

  Inject.GMHCallRax[0] := $48;
  Inject.GMHCallRax[1] := $FF;
  Inject.GMHCallRax[2] := $D0;

// FreeLibrary:
  Inject.FLMovRcxRax[0] := $48; //  ---+
  Inject.FLMovRcxRax[1] := $89; //  ---+--->  mov RCX, RAX
  Inject.FLMovRcxRax[2] := $C1; //  ---+

  Inject.FLMovRaxCommand := $B848;
  Inject.FLMovRaxArgument := Code + 95; // Code + смещение до адреса FreeLibrary

  Inject.FLMovRaxData[0] := $48; //  ---+
  Inject.FLMovRaxData[1] := $8B; //  ---+--->  mov RAX, [RAX]
  Inject.FLMovRaxData[2] := $00; //  ---+

  Inject.FLCallRax[0] := $48;
  Inject.FLCallRax[1] := $FF;
  Inject.FLCallRax[2] := $D0;

// ExitThread:
  Inject.ETMovRaxCommand := $B848;
  Inject.ETMovRaxArgument := Code + 103; // Code + смещение до адреса ExitThread

  Inject.ETMovRaxData[0] := $48; //  ---+
  Inject.ETMovRaxData[1] := $8B; //  ---+--->  mov RAX, [RAX]
  Inject.ETMovRaxData[2] := $00; //  ---+

  Inject.ETMovRcxCommand := $B948;
  Inject.ETMovRcxArgument := $0000000000000000; // ExitCode = 0

  Inject.ETCallRax[0] := $48;
  Inject.ETCallRax[1] := $FF;
  Inject.ETCallRax[2] := $D0;

// Выравниваем 64х-битный стек:
  Inject.AlignStackAtEnd := $90C3C35D20658D48;


// Записываем адреса библиотек:
  hKernel32 := LoadLibrary('kernel32.dll');

  if GMHAddress = 0 then
    Inject.AddrGetModuleHandle := UInt64(GetProcAddress(hKernel32, 'GetModuleHandleA'))
  else
    Inject.AddrGetModuleHandle := GMHAddress;

  if FLAddress = 0 then
    Inject.AddrFreeLibrary := UInt64(GetProcAddress(hKernel32, 'FreeLibrary'))
  else
    Inject.AddrFreeLibrary := FLAddress;

  if ETAddress = 0 then
    Inject.AddrExitThread  := UInt64(GetProcAddress(hKernel32, 'ExitThread'))
  else
    Inject.AddrExitThread := ETAddress;

  Move(ModuleName^, Inject.LibraryName, Length(ModuleName));

//  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

  // Записываем машинный код в выделенную память:
  if NtWriteVirtualMemory(ProcessHandle, Memory, @Inject, SizeOf(Inject), BytesWritten) <> 0 then Exit;

  // Выполняем машинный код в отдельном потоке:
  hThread := CreateRemoteThread(ProcessHandle, nil, 0, Memory, nil, 0, ThreadId);

  if hThread = 0 then
  begin
    VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);
    EmptyWorkingSet(ProcessHandle);
    CloseHandle(ProcessHandle);
    Exit;
  end;

  WaitForSingleObject(hThread, INFINITE);
  VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);

  CloseHandle(hThread);
  EmptyWorkingSet(ProcessHandle);
  CloseHandle(ProcessHandle);

  Result := True;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Инъекция кода напрямую из программы:
procedure InjectFunction(ProcessID: LongWord; InjectedFunction: Pointer; InjectedFunctionSize: NativeUInt);
var
  hProcess: NativeUInt;
  RemoteThreadBaseAddress: Pointer;
  BytesWritten: NativeUInt;
  RemoteThreadHandle: NativeUInt;
  RemoteThreadID: LongWord;
begin
  hProcess := OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
  if hProcess = 0 then
  begin
    MessageBox(0, 'Не удалось открыть процесс для записи!', 'Ошибка!', MB_ICONERROR);
    Exit;
  end;

  // Создаём память в процессе:
  RemoteThreadBaseAddress := VirtualAllocEx(hProcess, nil, InjectedFunctionSize, MEM_COMMIT + MEM_RESERVE, PAGE_EXECUTE_READWRITE);

  // Пишем в память наш код:
  NtWriteVirtualMemory(hProcess, RemoteThreadBaseAddress, InjectedFunction, InjectedFunctionSize, BytesWritten);
  if InjectedFunctionSize <> BytesWritten then
  begin
    MessageBox(0, 'Не удалось записать код в память удалённого процесса!', 'Ошибка!', MB_ICONERROR);
    VirtualFreeEx(hProcess, RemoteThreadBaseAddress, InjectedFunctionSize, MEM_RELEASE);
    Exit;
  end;

  RemoteThreadHandle := CreateRemoteThread(hProcess, nil, 0, RemoteThreadBaseAddress, nil, 0, RemoteThreadID);
  if RemoteThreadHandle = 0 then
  begin
    MessageBox(0, 'Не удалось запустить поток в удалённом процессе!', 'Ошибка!', MB_ICONERROR);
    VirtualFreeEx(hProcess, RemoteThreadBaseAddress, InjectedFunctionSize, MEM_RELEASE);
    Exit;
  end;
end;





//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
//
//                      #######    ####      ####
//                       ##   ##    ##        ##
//                       ##   ##    ##        ##
//                       ##   ##    ##   #    ##   #
//                      #######    #######   #######
//
//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH



// Заморозить все потоки процесса, кроме текущего:
procedure StopThreads;
var
  TlHelpHandle, CurrentThread, ThreadHandle, CurrentProcess: dword;
  ThreadEntry32: TThreadEntry32;
begin
  CurrentThread := GetCurrentThreadId;
  CurrentProcess := GetCurrentProcessId;
  TlHelpHandle := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if TlHelpHandle <> INVALID_HANDLE_VALUE then
  begin
    ThreadEntry32.dwSize := SizeOf(TThreadEntry32);
    if Thread32First(TlHelpHandle, ThreadEntry32) then
    repeat
      if (ThreadEntry32.th32ThreadID <> CurrentThread) and (ThreadEntry32.th32OwnerProcessID = CurrentProcess) then
      begin
        ThreadHandle := OpenThread(THREAD_SUSPEND_RESUME, false, ThreadEntry32.th32ThreadID);
        if ThreadHandle > 0 then
        begin
          SuspendThread(ThreadHandle);
          CloseHandle(ThreadHandle);
        end;
      end;
    until not Thread32Next(TlHelpHandle, ThreadEntry32);

    CloseHandle(TlHelpHandle);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Запустить все потоки процесса, кроме текущего:
procedure RunThreads;
var
  TlHelpHandle, CurrentThread, ThreadHandle, CurrentProcess: dword;
  ThreadEntry32: TThreadEntry32;
begin
  CurrentThread := GetCurrentThreadId;
  CurrentProcess := GetCurrentProcessId;
  TlHelpHandle := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if TlHelpHandle <> INVALID_HANDLE_VALUE then
  begin
    ThreadEntry32.dwSize := SizeOf(TThreadEntry32);
    if Thread32First(TlHelpHandle, ThreadEntry32) then
    repeat
      if (ThreadEntry32.th32ThreadID <> CurrentThread) and (ThreadEntry32.th32OwnerProcessID = CurrentProcess) then
      begin
        ThreadHandle := OpenThread(THREAD_SUSPEND_RESUME, false, ThreadEntry32.th32ThreadID);
        if ThreadHandle > 0 then
        begin
          ResumeThread(ThreadHandle);
          CloseHandle(ThreadHandle);
        end;
      end;
    until not Thread32Next(TlHelpHandle, ThreadEntry32);

    CloseHandle(TlHelpHandle);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Установка перехватчика:
function SetHook(OldProcAddress: Pointer; NewProcAddress: Pointer; out OriginalBlock: TOriginalBlock): Boolean;
var
  ReadBytes, WrittenBytes: NativeUInt;
  FarJump: TFarJump;
  OldProtect: Cardinal;
begin
{$IFDEF CPUX64}
  // x64:
  { 48 B8 [8 байт адреса] 50 C3 }
  FarJump.MovRaxCommand := $B848;           //  --+
  FarJump.MovRaxArgument := NewProcAddress; //  --+-->  mov RAX, NewProcAddress
  FarJump.PushRaxCommand := $50;            //  ----->  push RAX
  FarJump.RetCommand := $C3;                //  ----->  ret
{$ELSE}
  // х32:
  { 68 [4 байта адреса] C3 }
  FarJump.PushOp  := $68;                   //  --+
  FarJump.PushArg := NewProcAddress;        //  --+-->  push NewProcAddress
  FarJump.RetOp   := $C3;                   //  ----->  ret
{$ENDIF}

  StopThreads;
  VirtualProtect(OldProcAddress, SizeOf(TFarJump), PAGE_READWRITE, @OldProtect);
  FillChar(OriginalBlock, SizeOf(FarJump), #0);
  NtReadVirtualMemory(GetCurrentProcess, OldProcAddress, @OriginalBlock[0], SizeOf(FarJump), ReadBytes);
  NtWriteVirtualMemory(GetCurrentProcess, OldProcAddress, @FarJump, SizeOf(FarJump), WrittenBytes);
  Result := WrittenBytes <> 0;
  VirtualProtect(OldProcAddress, SizeOf(TFarJump), OldProtect, @OldProtect);
  RunThreads;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Снятие перехвата:
function UnHook(OriginalProcAddress: Pointer; OriginalBlock: TOriginalBlock): Boolean;
var
  WrittenBytes: NativeUInt;
  OldProtect: Cardinal;
begin
  StopThreads;
  VirtualProtect(OriginalProcAddress, SizeOf(TFarJump), PAGE_READWRITE, @OldProtect);
  NtWriteVirtualMemory(GetCurrentProcess, OriginalProcAddress, @OriginalBlock[0], SizeOf(TFarJump), WrittenBytes);
  Result := WrittenBytes <> 0;
  VirtualProtect(OriginalProcAddress, SizeOf(TFarJump), OldProtect, @OldProtect);
  RunThreads;
end;


//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH


function CBTProc(Code: Integer; wParam: Integer; lParam: Integer): Integer; stdcall;
begin
  Result := 0;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

function HookEmAll(out GlobalHookHandle: THandle): Boolean;
begin
  GlobalHookHandle := SetWindowsHookEx($FFFFFFFF, @CBTProc, hInstance, 0);
  Result := GlobalHookHandle <> 0;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure UnHookEmAll(GlobalHookHandle: THandle);
begin
  UnhookWindowsHookEx(GlobalHookHandle);
end;

end.
