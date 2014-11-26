unit MicroDAsm;

interface

type
  TREXStruct = record
    B: Boolean; // Extension of the ModR/M r/m field, SIB base field, or Opcode reg field
    X: Boolean; // Extension of the SIB index field
    R: Boolean; // Extension of the ModR/M reg field
    W: Boolean; // 0 = Operand size determined by CS.D; 1 = 64 Bit Operand Size
  end;

type
  TInstruction = record
    PrefixesSize   : Byte;
    LegacyPrefixes : array [0..3] of Byte;

    REXPresent : Boolean;
    REXOffset  : Byte;
    REXPrefix  : Byte;
    REXStruct  : TREXStruct;

    OpcodeOffset     : Byte;
    OpcodeIsExtended : Boolean;
    OpcodeSize       : Byte;
    Opcode           : array [0..2] of Byte;
    FullOpcode       : LongWord;

    ModRMPresent : Boolean;
    ModRMOffset  : Byte;
    ModRM        : Byte;

    SIBPresent : Boolean;
    SIBOffset  : Byte;
    SIB        : Byte;

    AddressDisplacementPresent : Boolean;
    AddressDisplacementOffset  : Byte;
    AddressDisplacementSize    : Byte;
    AddressDisplacement        : UInt64;

    ImmediateDataPresent : Boolean;
    ImmediateDataOffset  : Byte;
    ImmediateDataSize    : Byte;
    ImmediateData        : UInt64;
  end;

// GRP:
const
  GRP1 = 0;
  GRP2 = 1;
  GRP3 = 2;
  GRP4 = 3;

// Legacy Prefixes:
const
  PrefixNone = $00;

  // Legacy Prefix GRP 1:
  LockPrefix       = $F0;
  RepneRepnzPrefix = $F2;
  RepeRepzPrefix   = $F3;

  // Legacy Prefix GRP 2:
  CSOverridePrefix     = $2E;
  SSOverridePrefix     = $36;
  DSOverridePrefix     = $3E;
  ESOverridePrefix     = $26;
  FSOverridePrefix     = $64;
  GSOverridePrefix     = $65;
  BranchNotTakenPrefix = $2E; // ������ � Jcc
  BranchTakenPrefix    = $3E; // ������ � Jcc

  // Legacy Prefix GRP 3:
  OperandSizeOverridePrefix = $66;

  // Legacy Prefix GRP 4:
  AddressSizeOverridePrefix = $67;

// REX Prefix - ���������� 64�-������ ������ ���������, ����������� ����������� ��������:
const
  REXNone = $00;
  RexDiapason = [$40..$4F];

// ������:
const
  EXTENDED_OPCODE = $0F;
  ThirdByteOpcodeSignature = [$66, $F2, $F3];


//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

function LDasm(Code: Pointer; Is64Bit: Boolean; out Instruction: TInstruction): Byte;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

{$I MicroDAsmTables.inc}

implementation


function GetByte(BaseAddress: Pointer; Offset: LongWord): Byte; inline;
begin
  Result := Byte((Pointer(LongWord(BaseAddress) + Offset))^);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

function GetWord(BaseAddress: Pointer; Offset: LongWord): Word; inline;
begin
  Result := Word((Pointer(LongWord(BaseAddress) + Offset))^);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

function GetDWord(BaseAddress: Pointer; Offset: LongWord): LongWord; inline;
begin
  Result := Byte((Pointer(LongWord(BaseAddress) + Offset))^);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

function GetQWord(BaseAddress: Pointer; Offset: LongWord): UInt64; inline;
begin
  Result := UInt64((Pointer(LongWord(BaseAddress) + Offset))^);
end;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

function IsBitSet(Number, BitNumber: LongWord): Boolean; inline;
begin
  Result := (Number and (1 shl BitNumber)) <> 0;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

function IsNumberContains(Number, SubNumber: LongWord): Boolean; inline;
begin
  Result := (Number and SubNumber) = SubNumber;
end;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

procedure GetModRmParts(ModRM: Byte; out _Mod, _Reg, _RM: Byte); inline;
begin
  // 192 = 11 000 000
  // 56  =    111 000
  // 7   =        111

  _Mod := (ModRM and 192) shr 6;
  _Reg := (ModRM and 56) shr 3;
  _RM  := (ModRM and 7);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure GetSibParts(SIB: Byte; out _Scale, _Index, _Base: Byte); inline;
begin
  // 192 = 11 000 000
  // 56  =    111 000
  // 7   =        111

  _Scale := (SIB and 192) shr 6;
  _Index := (SIB and 56) shr 3;
  _Base  := (SIB and 7);
end;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

function IsModRmPresent(Opcode: LongWord; Size: LongWord): Boolean; inline;
begin
  Result := False;
  case Opcode of
    1: Result := (OneByteOpcodeFlags[Opcode] and OP_MODRM) = OP_MODRM;
    2: Result := (TwoBytesOpcodeFlags[Opcode] and OP_MODRM) = OP_MODRM;
    //3: ...
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

function IsSibPresent(ModRM: Byte): Boolean; inline;
begin
  //      Mod Reg R/M
  // 192 = 11 000 000b - Mod
  //   4 =        100b - R/M
  Result := ((ModRM and 192) <> 192) and ((ModRM and 4) = 4);
end;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

function LDasm(Code: Pointer; Is64Bit: Boolean; out Instruction: TInstruction): Byte;
var
  TempByte    : Byte;
  RexByte     : Byte;
  OpCodeByte  : Byte;
  ModRmByte   : Byte;
  SibByte     : Byte;
  I           : Byte;
  OperandSize : Byte;
  _Mod,   _Reg,   _RM   : Byte;
  _Scale, _Index, _Base : Byte;
begin
{

  ��������� ����������:

        GRP 1, 2, 3, 4                          7.....0   7.....0   7.....0
  +------------------------+-------------------+---------------------------+
  | Legacy Prefixes (opt.) | REX Prefix (opt.) | = OPCODE (1, 2, 3 byte) = +--+
  +------------------------+-------------------+---------------------------+  |
                                                                              |
      +-----------------------------------------------------------------------+
      |
      |   +-----+-----+-----+   +-------+-------+------+
      +-->| Mod | Reg | R/M | + | Scale | Index | Base |  +  d32|16|8|N + d32|16|8|N
          +-----+-----+-----+   +-------+-------+------+       Address     Immediate
            7-6   5-3   2-0        7-6     5-3    2-0       Displacement     Data

              Mod R/M Byte               SIB Byte


  ������� �������:
   1) �������� �������� (������������, �� 4� ����)
   2) ���� ��� �64 - �������� ������������ REX-�������, ���������� �� 64�-������ ���������.
   3) �������� ����� (�� ������ �� ��� ����, � ����������� �� ��������� � ������� ����� ������)
   4) �� ������� ������� ���������� ������� ����� ModRM � ������ ������
   5) �� ������� ModRM (���� ���������� ���������� ModRM) ���������� ������� SIB

}

  Result := 0;
  FillChar(Instruction, SizeOf(Instruction), #0);
  OperandSize := 0;

  // �������� Legacy Prefix ���� ����� (GRP 1 - GRP 4):
  for I := 0 to 3 do
  begin
    case GetByte(Code, 0) of
      LockPrefix       : Instruction.LegacyPrefixes[I] := LockPrefix;
      RepneRepnzPrefix : Instruction.LegacyPrefixes[I] := RepneRepnzPrefix;
      RepeRepzPrefix   : Instruction.LegacyPrefixes[I] := RepeRepzPrefix;
      CSOverridePrefix : Instruction.LegacyPrefixes[I] := CSOverridePrefix;
      SSOverridePrefix : Instruction.LegacyPrefixes[I] := SSOverridePrefix;
      DSOverridePrefix : Instruction.LegacyPrefixes[I] := DSOverridePrefix;
      ESOverridePrefix : Instruction.LegacyPrefixes[I] := ESOverridePrefix;
      FSOverridePrefix : Instruction.LegacyPrefixes[I] := FSOverridePrefix;
      GSOverridePrefix : Instruction.LegacyPrefixes[I] := GSOverridePrefix;
      // BranchNotTakenPrefix : Instruction.LegacyPrefixes[I] := BranchNotTakenPrefix;
      // BranchTakenPrefix    : Instruction.LegacyPrefixes[I] := BranchTakenPrefix;
      OperandSizeOverridePrefix : Instruction.LegacyPrefixes[I] := OperandSizeOverridePrefix;
      AddressSizeOverridePrefix : Instruction.LegacyPrefixes[I] := AddressSizeOverridePrefix;
    else
      Break;
    end;

    Inc(Instruction.PrefixesSize);
  end;

  Instruction.REXOffset := Instruction.PrefixesSize;

  // ���������� �������� ������ ������ REX'� - ����� REX'a ���,
  // � �������� ������ ��� �����:
  Instruction.OpcodeOffset := Instruction.REXOffset;

  // �������� REX-�������:
  if Is64Bit then
  begin
    TempByte := GetByte(Code, Instruction.REXOffset);

    // ���������, �������� �� ���� REX-��������� [$40..$4F]:
    if TempByte in RexDiapason then
    begin
      Inc(Result);

      RexByte := TempByte;

      Instruction.REXPrefix := RexByte;

      Instruction.REXStruct.B := IsBitSet(RexByte, 0);
      Instruction.REXStruct.X := IsBitSet(RexByte, 1);
      Instruction.REXStruct.R := IsBitSet(RexByte, 2);
      Instruction.REXStruct.W := IsBitSet(RexByte, 3);

      // ������������ REX:
      case Instruction.REXStruct.W of
        True: if (Instruction.LegacyPrefixes[GRP1] = OperandSizeOverridePrefix) or
                 (Instruction.LegacyPrefixes[GRP2] = OperandSizeOverridePrefix) or
                 (Instruction.LegacyPrefixes[GRP3] = OperandSizeOverridePrefix) or
                 (Instruction.LegacyPrefixes[GRP4] = OperandSizeOverridePrefix)
              then
                OperandSize := 4  // 4 ����� = 32 ����
              else
                OperandSize := 0; // ������ �������� ������������ ����� CS.D

        False: OperandSize := 8; // 8 ���� = 64 ����
      end;

      // ����������� �������� ������:
      Inc(Instruction.OpcodeOffset);

    // if byte is REX-byte <-
    end;

  // if Is64Bit then <-
  end;


  // ��������� �����:
  OpCodeByte := GetByte(Code, Instruction.OpcodeOffset);
  Instruction.OpcodeIsExtended := OpCodeByte = EXTENDED_OPCODE;

  case Instruction.OpcodeIsExtended of
    True:
    begin
      // ��������� ����������� � ���������� ������:
      if Instruction.OpcodeOffset > 0 then
      begin
        if GetByte(Code, Instruction.OpcodeOffset - 1) in ThirdByteOpcodeSignature then
        begin
          // ���������� �����:
          Instruction.LegacyPrefixes[Instruction.PrefixesSize - 1] := PrefixNone;
          Dec(Instruction.OpcodeOffset);

          Instruction.OpcodeSize := 3;
          Instruction.Opcode[0] := GetByte(Code, Instruction.OpcodeOffset);
          Instruction.Opcode[1] := GetByte(Code, Instruction.OpcodeOffset + 1);
          Instruction.Opcode[2] := GetByte(Code, Instruction.OpcodeOffset + 2);
        end
        else
        begin
          // ����������� �����:
          Instruction.OpcodeSize := 2;
          Instruction.Opcode[0] := OpCodeByte;
          Instruction.Opcode[1] := GetByte(Code, Instruction.OpcodeOffset + 1);
        end;
      end
      else
      begin
        // ����������� �����:
        Instruction.OpcodeSize := 2;
        Instruction.Opcode[0] := OpCodeByte;
        Instruction.Opcode[1] := GetByte(Code, Instruction.OpcodeOffset + 1);
      end;
    end;

    False:
    begin
      Instruction.OpcodeSize := 1;
      Instruction.Opcode[0] := OpCodeByte;
    end;
  end;

  Instruction.FullOpcode := (Instruction.Opcode[0] shl 16) + (Instruction.Opcode[1] shl 8) + Instruction.Opcode[0];


  Instruction.ModRMPresent := IsModRmPresent(Instruction.FullOpcode, Instruction.OpcodeSize);
  if Instruction.ModRMPresent then
  begin
    Inc(Result);
    Instruction.ModRMOffset := Instruction.OpcodeOffset + Instruction.OpcodeSize;

    // ��������� ���� ModR/M:
    ModRmByte := GetByte(Code, Instruction.ModRMOffset);
    Instruction.SIBPresent := IsSibPresent(ModRmByte);
    GetModRmParts(ModRmByte, _Mod, _Reg, _RM);

    if Instruction.SIBPresent then
    begin
      Inc(Result);
      Instruction.SIBOffset := Instruction.ModRMOffset + 1;
      SibByte := GetByte(Code, Instruction.SIBOffset);
      GetSibParts(SibByte, _Scale, _Index, _Base);

      if _Base = 5 { 101b } then
      begin
        Instruction.AddressDisplacementPresent := True;

        case _Mod of
          0: { 00b }
          begin
            //Instruction.AddressDisplacementSize :=
          end;

          1: { 01b }
          begin

          end;

          2: { 10b }
          begin

          end;
        end;
      end;
    end
    else
    begin

    end;
  end;

  Result := Result + Instruction.PrefixesSize + Instruction.OpcodeSize;
end;

end.
