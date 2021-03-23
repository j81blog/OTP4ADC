<#
.SYNOPSIS
    Edit, change and create OTP tokens to be used with Citrix ADC Native OTP
.DESCRIPTION
    Edit, change and create OTP tokens to be used with Citrix ADC Native OTP.
    The user running the script must have permissions to change the users attribute.
.PARAMETER Attribute
    (Optional) Pre-set the Attribute that contains the OTP token(s).
    If not configured you can do this in the GUI.
    Default, the value "userParameters" will be used.
.PARAMETER GatewayURI
    (Optional) Pre-set the Gateway URI.
    If not configured you can do this in the GUI.
.PARAMETER QRSize
    The size for height and width for the generated QR image in pixels.
    Default, 300 
.EXAMPLE
    .\OTP4ADC.ps1
    Run the script with no parameters
.EXAMPLE
    .\OTP4ADC.ps1 -attribute "extensionAttribute1" -GatewayURI "gw.domain.com"
    Run the script and use "extensionAttribute1" as attribute name and "gw.domain.com" as Gateway URI
.NOTES
    File Name : OTP4ADC.ps1
    Version   : v0.4.4
    Author    : John Billekens
    Requires  : PowerShell v5.1 and up
                Permission to change the user (attribute)
.LINK
    https://blog.j81.nl
#>

[CmdletBinding(DefaultParameterSetName = "GUI")]
Param(
    [Parameter(ParameterSetName = "GUI")]
    [Parameter(ParameterSetName = "CommandLine", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$GatewayURI = "",
    
    [Parameter(ParameterSetName = "GUI")]
    [Parameter(ParameterSetName = "CommandLine", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$Attribute = "userParameters",

    [Parameter(ParameterSetName = "GUI")]
    [Switch]$NoHide,
    
    [Parameter(ParameterSetName = "GUI")]
    [Parameter(ParameterSetName = "CommandLine")]
    [ValidateNotNullOrEmpty()]
    [Int]$QRSize = 300,
    
    [Parameter(ParameterSetName = "CommandLine")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("1", "2", "3")]
    [String]$TokenText = "2",

    [Parameter(ParameterSetName = "GUI")]
    [Switch]$Console,

    [Parameter(ParameterSetName = "CommandLine", Mandatory = $true)]
    [String]$Username,
    
    [Parameter(ParameterSetName = "CommandLine", Mandatory = $true)]
    [String]$DeviceName,
    
    [Parameter(ParameterSetName = "CommandLine")]
    [Switch]$ReplaceTokens,
    
    [Parameter(ParameterSetName = "CommandLine", Mandatory = $true)]
    [String]$ExportPath
)
$AppVersion = "v0.4.4"

#region functions
function New-QRTOTPImage {
    <#
        .SYNOPSIS
        Creates a QR code graphic containing a URI
        .DESCRIPTION
        Creates a QR code graphic in png format that - when scanned by a smart device - opens a URI/URL in your webapp
        .PARAMETER URI
        The URI
        .PARAMETER Width
        Height and Width of generated graphics (in pixels). Default is 100.
        .PARAMETER Show
        Opens the generated QR code in associated program
        .PARAMETER OutPath
        Path to generated png file. When omitted, a temporary file name is used.
        .EXAMPLE
        New-QRTOTPImage -URI "https://github.com/TobiasPSP/Modules.QRCodeGenerator" -Width 50 -Show -OutPath "$home\Desktop\qr.png"
        Creates a QR code png graphics on your desktop, and opens it with the associated program
        .NOTES
        Compatible with all PowerShell versions including PowerShell 6/Core
        Uses binaries from https://github.com/codebude/QRCoder/wiki
        .LINK
        https://github.com/TobiasPSP/Modules.QRCodeGenerator
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [alias("URL")]
        [System.Uri]
        $URI,

        [ValidateRange(10, 2000)]
        [int]
        $Width = $Script:QRSize,

        [Switch]
        $Show,
        
        [Switch]
        $OutStream,
        
        [string]
        $OutPath = "$env:temp\qrcode.png"
    )
    Write-Verbose "Starting function : New-QRTOTPImage"
    $payload = @"
$($URI.AbsoluteUri)
"@

    $generator = New-Object -TypeName QRCoder.QRCodeGenerator
    $data = $generator.CreateQrCode($payload, 'Q')
    $code = new-object -TypeName QRCoder.PngByteQRCode -ArgumentList ($data)
    $byteArray = $code.GetGraphic($Width)
    
    #Due to bug in output size, we resize the QR
    Add-Type -AssemblyName "System.Drawing"
    $GeneratedQR = [System.Drawing.Image]::FromStream( $( New-Object -TypeName 'System.IO.MemoryStream' -ArgumentList (, $byteArray) ) )
    $Height = $Width
    if ($GeneratedQR.Width -ne $Width) {
        Write-Verbose "Resizing to $Width"
        $Bitmap = New-Object -TypeName System.Drawing.Bitmap -ArgumentList $Width, $Height
        $NewQR = [System.Drawing.Graphics]::FromImage($Bitmap)
        #$NewQR.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        #$NewQR.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        #$NewQR.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $NewQR.DrawImage($GeneratedQR, $(New-Object -TypeName System.Drawing.Rectangle -ArgumentList 0, 0, $Width, $Height))
        if ($OutStream) {
            $MemoryStream = New-Object -TypeName 'System.IO.MemoryStream'
            $Bitmap.Save($MemoryStream, [System.Drawing.Imaging.ImageFormat]::Png)
        } else {
            $Bitmap.Save($OutPath)
        }
        $GeneratedQR.Dispose()
        $Bitmap.Dispose()
        $NewQR.Dispose()
    } else {
        [System.IO.File]::WriteAllBytes($OutPath, $byteArray)
    }
    if ($Show) { Invoke-Item -Path $outPath }
    Write-Verbose "Ending function   : New-QRTOTPImage"
    if ($OutStream) { return $MemoryStream }
}

<#
function Get-OTPSecret {
    [cmdletbinding()]
    param(
        [Int]$Length = 40
    )
    $base32Secret = $null
    while ($null -eq $base32Secret) {
        try{
            $hexSecret = ((($Length) | ForEach-Object { ((1..$_) | ForEach-Object { ('{0:X}' -f (Get-random(16))) }) }) -Join "").ToLower()
            $byteSecret = $hexSecret -replace '^0x', '' -split "(?<=\G\w{2})(?=\w{2})" | ForEach-Object { [Convert]::ToByte( $_, 16 ) }
            $byteArrayAsBinaryString = -join $byteSecret.ForEach{ [Convert]::ToString($_, 2).PadLeft(8, '0') }
            $base32Secret = [regex]::Replace($byteArrayAsBinaryString, '.{5}', {
                    param($Match)
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[[Convert]::ToInt32($Match.Value, 2)]
                })
        } catch {
            $base32Secret = $null
        }
    }
    return $base32Secret
}  

#>

function Get-OTPSecret {
    [cmdletbinding()]
    param  ()
    Write-Verbose "Starting function : Get-OTPSecret"
    $Base32Chars = @("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "2", "3", "4", "5", "6", "7")
    $HexString = "$(([char[]] ([char]'A'..[char]'F') + 0..9 | Sort-Object { Get-Random })[0..15] -join '')$(([char[]] ([char]'A'..[char]'F') + 0..9 | Sort-Object { Get-Random })[0..15] -join '')"
    $Array = @()
    for ($i = 0; $i -lt $HexString.Length / 2; $i++) { 
        $Array += [System.Convert]::ToInt32($($HexString.Substring($i * 2, 2)), 16) 
    }
    for ($i = 0; $i -lt $Array.Length; $i++) {
        $Byte = [convert]::ToString($Array[$i], 2)
        while ($Byte.Length -lt 8) {
            $Byte = "0" + $Byte
        }
        $Bytes += $Byte
    }
    while (($Bytes.Length % 5) -gt 0 ) {
        $Bytes = $Bytes + "0"    
    }
    for ($i = 0; $i -lt $Bytes.Length / 5; $i++) {
        $Base32Secret = "$Base32Secret$($Base32Chars[$([convert]::ToInt32($($Bytes.Substring($i*5, 5)),2))])"
    }
    Write-Verbose "Ending function   : Get-OTPSecret"
    return $Base32Secret
}

function Convert-B32toByte {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$Value
    )
    Write-Verbose "Starting function : Convert-B32toByte"
    $Base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $Binary = ""
    $CharacterArray = $Value.ToUpper().ToCharArray()
    foreach ($Character in $CharacterArray) {
        $Binary += [Convert]::ToString($Base32Chars.IndexOf($Character), 2).PadLeft(5, "0")
    }
    for ($i = 0; $i -le ($Binary.Length - 8); $i += 8) {
        [Byte][Convert]::ToInt32($Binary.Substring($i, 8), 2)
    }
    Write-Verbose "Ending function   : Convert-B32toByte"
}

function Get-OTPToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$B32Secret,

        # TOTP Token Length
        [Int]$OTPLength = 6,

        # OTP time window in seconds
        [Int]$TimeWindow = 30 
    )
    Write-Verbose "Starting function : Get-OTPToken"
    #Unix epoch time in UTC
    #Source https://gist.github.com/jonfriesen/234c7471c3e3199f97d5
    $EpochTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $KeyedHashAlgorithm = New-Object -TypeName "System.Security.Cryptography.HMACSHA1"
    try {
        $KeyedHashAlgorithm.Key = Convert-B32toByte -Value $B32Secret
        $CalculatedInterval = [BitConverter]::GetBytes([int64][math]::Floor($epochTime / $TimeWindow))
        if ([BitConverter]::IsLittleEndian) { [array]::Reverse($CalculatedInterval) }
        $CompHash = $KeyedHashAlgorithm.ComputeHash($CalculatedInterval)
        $Offset = $CompHash[($CompHash.Length - 1)] -band 0xf
        $fullOTP = ($CompHash[$offset] -band 0x7f) * [math]::pow(2, 24)
        $fullOTP += ($CompHash[$offset + 1] -band 0xff) * [math]::pow(2, 16)
        $fullOTP += ($CompHash[$offset + 2] -band 0xff) * [math]::pow(2, 8)
        $fullOTP += ($CompHash[$offset + 3] -band 0xff)
        $OTPToken = ($fullOTP % ([math]::pow(10, $OTPLength))).ToString("0" * $OTPLength)
        return [PSCustomObject]@{
            OTP       = $OTPToken
            Remaining = ($TimeWindow - ($epochTime % $TimeWindow))
            ValidTo   = (Get-Date).AddSeconds(($TimeWindow - ($epochTime % $TimeWindow)))
        }
    } catch {
        Write-Verbose "Get-OTPToken Error: $($_.Exception.Message)"
        return $null
    }
    Write-Verbose "Ending function   : Get-OTPToken"
}

function Save-File {
    [CmdletBinding()]
    Param(
        [string]$InitialDirectory = $([System.Environment]::GetFolderPath("mydocuments")),
        
        [String]$FileName,
        
        [String]$Filter = "All files (*.*)| *.*"
    )
    Write-Verbose "Starting function : Save-File"
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $OpenFileDialog.initialDirectory = $InitialDirectory
    if (-Not [String]::IsNullOrEmpty($FileName)) {
        $OpenFileDialog.FileName = $FileName
    }
    $OpenFileDialog.filter = $Filter
    $OpenFileDialog.ShowDialog() | Out-Null
    Write-Verbose "FilePath: `"$($OpenFileDialog.filename)`""
    Write-Verbose "Ending function   : Save-File"
    return $OpenFileDialog.filename
} 

function ConvertFrom-Attribute {
    [CmdLetBinding()]
    [OutputType('PSCustomObject')]
    param(
        [String]$Data
    )
    Write-Verbose "Starting function : ConvertFrom-Attribute"

    if ($Data.Length -gt 2) {
        $Result = $Data.Substring(2).Split(',') | ForEach-Object { [PSCustomObject]@{
                DeviceName = $($_.Split('=')[0])
                Secret     = $(($_.Replace('&', '').Split('=')[1]))
            } } | Where-Object { $_.Secret } | Sort-Object DeviceName
    }
    Write-Verbose "Ending function   : ConvertFrom-Attribute"
    return $Result | Sort-Object DeviceName
}

function Initialize-GUI {
    Write-Verbose "Starting function : Initialize-GUI"
    $SyncHash.Form.WindowStartupLocation = [System.Windows.WindowStartupLocation]::CenterScreen
    $SyncHash.WPFControl_tbAttribute.Text = $SyncedVariables.Attribute
    $SyncedVariables.OTPDevices = @()
    $SyncedVariables.DeviceSecrets = @()
    Reset-GUIForm
    Write-Verbose "Ending function   : Initialize-GUI"
}

function Update-Gui {
    #Fixes the "freeze" problem
    Write-Verbose "Starting function : Update-Gui"
    # Basically WinForms Application.DoEvents()
    try { $SyncHash.App.Dispatcher.Invoke([Windows.Threading.DispatcherPriority]::Background, [action] { }) } catch { }
    Write-Verbose "Ending function   : Update-Gui"
}

function Invoke-CleanGUIQRImage {
    Write-Verbose "Starting function : Invoke-CleanGUIQRImage"
    $SyncHash.WPFControl_btnGenerateQR.Content = "Generate QR"
    if ($SyncHash.WPFControl_btnGenerateQR.IsEnabled) { $SyncHash.WPFControl_btnGenerateQR.IsEnabled = $false }
    if ($SyncHash.WPFControl_btnExportQR.IsEnabled) { $SyncHash.WPFControl_btnExportQR.IsEnabled = $false }
    $SyncHash.WPFControl_ImgQR.Source = $null
    $SyncHash.WPFControl_lbTokenUserText.Content = ""
    #$SyncHash.WPFControl_ImgQR.Visibility = [System.Windows.Visibility]::Hidden
    if ($SyncedVariables.QRGenerationPossible) { $SyncHash.WPFControl_lblQR.Content = "" }
    $SyncedVariables.QRImage = $null
    Invoke-ValidateGUIQR
    Invoke-ValidateAddSecret
    Write-Verbose "Ending function   : Invoke-CleanGUIQRImage"
}

function Get-GUIQRImage {
    Write-Verbose "Starting function : Get-GUIQRImage"
    #Invoke-CleanGUIQRImage
    if ($SyncHash.WPFControl_btnGenerateQR.IsEnabled) { $SyncHash.WPFControl_btnGenerateQR.IsEnabled = $false }
    $SyncHash.WPFControl_btnGenerateQR.Content = "Generating QR..."
    $SyncHash.WPFControl_lblQR.Content = "Loading QR..."
    Write-Verbose "Ending function   : Get-GUIQRImage"
}

function Show-QR {
    Write-Verbose "Starting function : Show-QR"
    #$SyncHash.WPFControl_ImgQR.Visibility = [System.Windows.Visibility]::Visible
    $SyncHash.WPFControl_lblQR.Content = ""
    if (-Not $SyncHash.WPFControl_btnExportQR.IsEnabled) { $SyncHash.WPFControl_btnExportQR.IsEnabled = $true }
    $SyncHash.WPFControl_btnExportQR.Focus() | Out-Null
    $SyncHash.WPFControl_btnGenerateQR.Content = "Generate QR"
    if ($SyncHash.WPFControl_btnGenerateQR.IsEnabled -eq $false) { $SyncHash.WPFControl_btnGenerateQR.IsEnabled = $true }
    Write-Verbose "Ending function   : Show-QR"
}

function Search-User {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Name
    )
    Write-Verbose "Starting function : Search-User"
    try {
        if ($Script:AlternativeLDAPModule) {
            $Params = @{
                Attributes = @($SyncedVariables.Attribute)
                Name       = $Name
            }
            $ADUsers = Get-AdsiADUser @Params
        } else { 
            $Params = @{
                Properties = @($SyncedVariables.Attribute)
                LDAPFilter = "(&(objectCategory=person)(objectClass=user)(|(Name=*$Name*)(UserPrincipalName=*$Name*)(SamAccountName=*$Name*)(Sn=*$Name*)(GivenName=*$Name*)))"
            }
            if (-Not ($null -eq $SyncedVariables.LDAPCredential -or $SyncedVariables.LDAPCredential -eq [PSCredential]::Empty)) {
                $Params.Credential = $SyncedVariables.LDAPCredential
            }
            if (-Not [String]::IsNullOrEmpty($($SyncedVariables.Settings.LDAPSettings.LDAPServer))) {
                $Params.Server = $SyncedVariables.Settings.LDAPSettings.LDAPServer
            }
            $ADUsers = Get-ADUser @Params
        }
       
        $Results = $ADUsers | ForEach-Object {
            $Username = $_.SamAccountName
            if ($Script:AlternativeLDAPModule) {
                $Surname = $_.sn
            } else {
                $Surname = $_.Surname
            }
            [PSCustomObject]@{
                SamAccountName    = $Username
                GivenName         = $_.GivenName
                Surname           = $Surname
                Name              = $_.Name
                Attribute         = $_."$($SyncedVariables.Attribute)"
                DistinguishedName = $_.DistinguishedName
                UserPrincipalName = $_.UserPrincipalName
            } }
    } catch {
        Write-Verbose "Caught an error, $($_.Exception.Message)"
        $null = [System.Windows.MessageBox]::Show("$($_.Exception.Message)", "Error!", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
    Write-Verbose "Ending function   : Search-User"
    return $Results 
}

function Invoke-CleanGUIUser {
    Write-Verbose "Starting function : Invoke-CleanGUIUser"
    if (-Not $SyncedVariables.CleanGUIUser) {
        if ($SyncedVariables.Saved) {
            $Continue = $true
        } else {
            $result = [System.Windows.MessageBox]::Show("There are unsaved changes!`nDo you want to continue and loose the made changes?", "Unsaved changes", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Exclamation)
            switch ($result.ToString()) {
                "Yes" { $Continue = $true }
                "No" { $Continue = $false }
                Default { $Continue = $false }
            }
        
        }
        if ($Continue) {
            $SyncHash.WPFControl_lvUsernames.ItemsSource = $null
            $SyncHash.WPFControl_tbUsername.Text = ""
            $SyncHash.WPFControl_lvOtps.ItemsSource = $null
            if ($SyncHash.WPFControl_btnDeleteOtpSecret.IsEnabled) { $SyncHash.WPFControl_btnDeleteOtpSecret.IsEnabled = $false }
            if ($SyncHash.WPFControl_btnSaveOtp.IsEnabled) { $SyncHash.WPFControl_btnSaveOtp.IsEnabled = $false }
            if ($SyncHash.WPFControl_btnExportPosh.IsEnabled) { $SyncHash.WPFControl_btnExportPosh.IsEnabled = $false }
            $SyncedVariables.Saved = $true
            $SyncedVariables.DeviceSecrets = @()
            $SyncedVariables.OTPDevices = @()
            Invoke-CleanGUIQR
            Invoke-CleanOTPToken
            Invoke-UpdateTokenText
        }
        $SyncedVariables.CleanGUIUser = $true
    } else {
        Write-Verbose "Invoke-CleanGUIUser, nothing to do."
    }
    Write-Verbose "Ending function   : Invoke-CleanGUIUser"
}

function Invoke-CleanOTPToken {
    Write-Verbose "Starting function : Invoke-CleanOTPToken"
    $SyncedVariables.OTPUpdate = $False
    $SyncedVariables.OTPToken = $null
    try { $PoSH.EndInvoke($SyncedVariables.handle) } catch { }
    if ($SyncHash.WPFControl_gbToken.IsEnabled) { $SyncHash.WPFControl_gbToken.IsEnabled = $false }
    if ($SyncHash.WPFControl_btnViewTOTPToken.IsEnabled) { $SyncHash.WPFControl_btnViewTOTPToken.IsEnabled = $false }
    $SyncHash.WPFControl_tbTOTPToken.Text = "------"
    $SyncHash.WPFControl_pbTOTPToken.Value = 0
    Write-Verbose "Ending function   : Invoke-CleanOTPToken"
}

function Invoke-CleanGUIQR {
    Write-Verbose "Starting function : Invoke-CleanGUIQR"
    $SyncHash.WPFControl_tbSecret.Text = ""
    $SyncHash.WPFControl_tbDeviceName.Text = ""
    $SyncHash.WPFControl_tbGateway.Text = $GatewayURI
    if ($SyncHash.WPFControl_btnAddQR.IsEnabled) { $SyncHash.WPFControl_btnAddQR.IsEnabled = $false }
    Invoke-CleanGUIQRImage
    Write-Verbose "Ending function   : Invoke-CleanGUIQR"
}

function Reset-GUIForm {
    [CmdLetBinding()]
    param()
    Write-Verbose "Starting function : Reset-GUIForm"
    Invoke-CleanGUIUser
    $SyncHash.WPFControl_tbUsername.Focus() | Out-Null
    Write-Verbose "Ending function   : Reset-GUIForm"
}

function Save-OtpToUser {
    Write-Verbose "Starting function : Save-OtpToUser"
    $SelectedUser = $SyncHash.WPFControl_lvUsernames.SelectedItem
    $DistinguishedName = $SelectedUser.DistinguishedName
    try {
        if ($SyncedVariables.DeviceSecrets.Count -gt 0) {
            $NewOTP = @()
            ForEach ($Item in $SyncedVariables.DeviceSecrets) {
                $NewOTP += "{0}={1}" -f $Item.DeviceName, $Item.Secret
            }
            $NewOTPString = "#@$($NewOTP -Join '&,')&,"
            Write-Verbose "New OTP AD User String: `"$NewOTPString`""
            #$SyncedVariables.DeviceName = $SyncHash.WPFControl_tbDeviceName.text
            if ($Script:AlternativeLDAPModule) {
                $Params = @{
                    DistinguishedName = $DistinguishedName
                    Attribute         = $SyncedVariables.Attribute
                    NewValue          = $NewOTPString
                }
                Set-AdsiADUser @Params
            } else {
                $Params = @{
                    Replace  = @{ "$($SyncedVariables.Attribute)" = $NewOTPString }
                    Identity = $DistinguishedName
                }
                if (-Not ($null -eq $SyncedVariables.LDAPCredential -or $SyncedVariables.LDAPCredential -eq [PSCredential]::Empty)) {
                    $Params.Credential = $SyncedVariables.LDAPCredential
                }
                if (-Not [String]::IsNullOrEmpty($($SyncedVariables.Settings.LDAPSettings.LDAPServer))) {
                    $Params.Server = $SyncedVariables.Settings.LDAPSettings.LDAPServer
                }
                Set-ADUser @Params
            }
        } else {
            Write-Verbose "No OTP for user, save empty string"
            $NewOTPString = $null
            if ($Script:AlternativeLDAPModule) {
                $Params = @{
                    DistinguishedName = $DistinguishedName
                    Attribute         = $SyncedVariables.Attribute
                    NewValue          = $null
                }
                Set-AdsiADUser @Params
            } else {
                $Params = @{
                    Clear    = @("$($SyncedVariables.Attribute)")
                    Identity = $DistinguishedName
                }
                if (-Not ($null -eq $SyncedVariables.LDAPCredential -or $SyncedVariables.LDAPCredential -eq [PSCredential]::Empty)) {
                    $Params.Credential = $SyncedVariables.LDAPCredential
                }
                if (-Not [String]::IsNullOrEmpty($($SyncedVariables.Settings.LDAPSettings.LDAPServer))) {
                    $Params.Server = $SyncedVariables.Settings.LDAPSettings.LDAPServer
                }
                Set-ADUser @Params
            }
        }
    } catch {
        $null = [System.Windows.MessageBox]::Show("$($_.Exception.Message)", "Error!", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
    $SyncedVariables.Saved = $true
    Write-Verbose "Ending function   : Save-OtpToUser"
}

function Save-OtpToUserExportCommand {
    Write-Verbose "Starting function : Save-OtpToUserExportCommand"
    $SelectedUser = $SyncHash.WPFControl_lvUsernames.SelectedItem
    $DistinguishedName = $SelectedUser.DistinguishedName
    if ($SyncedVariables.DeviceSecrets.Count -gt 0) {
        $NewOTP = @()
        ForEach ($Item in $SyncedVariables.DeviceSecrets) {
            $NewOTP += "{0}={1}" -f $Item.DeviceName, $Item.Secret
        }
        $NewOTPString = "#@$($NewOTP -Join '&,')&,"
        Write-Verbose "New OTP AD User String: `"$NewOTPString`""
        #$SyncedVariables.DeviceName = $SyncHash.WPFControl_tbDeviceName.text
        $ExportPoSHCommand = 'Set-ADUser -Identity "{0}" -Replace @{{ "{1}" = "{2}" }}' -f $DistinguishedName, $SyncedVariables.Attribute, $NewOTPString
    } else {
        Write-Verbose "No OTP for user, save empty string"
        $NewOTPString = $null
        $ExportPoSHCommand = 'Set-ADUser -Identity "{0}" -Clear @("{1}")' -f $DistinguishedName, $SyncedVariables.Attribute
    }
    $ExportPoSHCommand | clip.exe
    $result = [System.Windows.MessageBox]::Show("The PowerShell command to make the necessary changes was copied to the clipboard.`nClean the current screen? Changes are not saved to the selected user unless you run the copied command!", "PowerShell Command", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
    Write-Verbose "Result: $result"
    switch ($result) {
        "Yes" { $SyncedVariables.Saved = $true }
        "No" { $SyncedVariables.Saved = $false }
        Default { $SyncedVariables.Saved = $true }
    }
    Write-Verbose "Ending function   : Save-OtpToUserExportCommand"
}

function Invoke-UpdateTokenText {
    Write-Verbose "Starting function : Invoke-UpdateTokenText"
    $SelectedItem = $SyncHash.WPFControl_lvUsernames.SelectedItem
    $GatewayURI = $SyncHash.WPFControl_tbGateway.Text
    $UserPrincipalName = $SelectedItem.UserPrincipalName
    $SamAccountName = $SelectedItem.SamAccountName
    if ([String]::IsNullOrEmpty($GatewayURI)) {
        $GatewayURI = 'gateway.domain.com'
    }
    if ([String]::IsNullOrEmpty($SamAccountName)) {
        $SamAccountName = 'username'
    }
    if ([String]::IsNullOrEmpty($UserPrincipalName)) {
        $UserPrincipalName = 'username@domain.corp'
    }
    $NewTokenTextOption1 = $('{0}' -f $UserPrincipalName)
    $NewTokenTextOption2 = $('{0}@{1}' -f $SamAccountName, $GatewayURI)
    $NewTokenTextOption3 = $('{0}@{1}' -f $UserPrincipalName, $GatewayURI)
    $NewTokenTextOption0 = $('{0}' -f $UserPrincipalName)

    $SyncHash.WPFControl_rbTokenTextOption1.Content = '[1] {0}' -f $NewTokenTextOption1
    $SyncHash.WPFControl_rbTokenTextOption2.Content = '[2] {0}' -f $NewTokenTextOption2
    $SyncHash.WPFControl_rbTokenTextOption3.Content = '[3] {0}' -f $NewTokenTextOption3
    # "TokenText: $($SyncedVariables.TokenText)"
    switch ($SyncedVariables.TokenText) {
        "1" {
            # "(1) username@domain.com"
            $SyncedVariables.SelectedTokenText = $NewTokenTextOption1
            Break
        }
        "2" {
            # "(2) username@gateway.domain.com"
            $SyncedVariables.SelectedTokenText = $NewTokenTextOption2
            Break
        }
        "3" {
            # "(3) username@domain.com@gateway.domain.com"
            $SyncedVariables.SelectedTokenText = $NewTokenTextOption3
            Break
        }
        Default {
            Write-Verbose "(UNKNOWN) Could not match the TokenText ID! Using the default value."
            $SyncedVariables.SelectedTokenText = $NewTokenTextOption0
            Break
        }
    }
    Write-Verbose "Ending function   : Invoke-UpdateTokenText"
}
function Invoke-ValidateGUIQR {
    Write-Verbose "Starting function : Invoke-ValidateGUIQR"
    Update-Gui
    if (([String]::IsNullOrEmpty($($SyncHash.WPFControl_tbGateway.Text))) -or ([String]::IsNullOrEmpty($($SyncHash.WPFControl_tbDeviceName.Text))) -or ([String]::IsNullOrEmpty($($SyncHash.WPFControl_tbSecret.Text)))) {
        if ($SyncHash.WPFControl_btnGenerateQR.IsEnabled) { $SyncHash.WPFControl_btnGenerateQR.IsEnabled = $false }
    } else {
        if (-Not $SyncHash.WPFControl_btnGenerateQR.IsEnabled) { $SyncHash.WPFControl_btnGenerateQR.IsEnabled = $true }
    }
    Write-Verbose "Ending function   : Invoke-ValidateGUIQR"
}

function Invoke-ValidateAddSecret {
    Write-Verbose "Starting function : Invoke-ValidateAddSecret"
    if (([String]::IsNullOrEmpty($($SyncHash.WPFControl_tbDeviceName.Text))) -or ([String]::IsNullOrEmpty($($SyncHash.WPFControl_tbSecret.Text)))) {
        if ($SyncHash.WPFControl_btnAddQR.IsEnabled) { $SyncHash.WPFControl_btnAddQR.IsEnabled = $false }
    } else {
        if (-Not $SyncHash.WPFControl_btnAddQR.IsEnabled) { $SyncHash.WPFControl_btnAddQR.IsEnabled = $true }
    }
    Write-Verbose "Ending function   : Invoke-ValidateAddSecret"
}

function Invoke-SearchADUser {
    Write-Verbose "Starting function : Invoke-SearchADUser"
    if ([String]::IsNullOrEmpty($($SyncHash.WPFControl_tbUsername.Text))) {
        $null = [System.Windows.MessageBox]::Show("The Username field is empty!", "Username Empty", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    } else {
        $Results = Search-User -Name $SyncHash.WPFControl_tbUsername.Text
        $SyncHash.WPFControl_lvUsernames.ItemsSource = @($Results)
        if ($SyncHash.WPFControl_lvUsernames.Items.Count -eq 1) {
            $SyncHash.WPFControl_lvUsernames.SelectedIndex = 0
        }
        $SyncedVariables.CleanGUIUser = $false
    }
    Write-Verbose "Ending function   : Invoke-SearchADUser"
}

function Start-App {
    if (-Not $Script:AppStarted) {
        Write-Verbose "Starting function : Start-App"
        try {
            Invoke-LoadModules
            Invoke-LoadAppImage
            Initialize-GUI
            $Script:AppStarted = $true
        } catch { "ERROR: $($_.Exception.Message)" }
        Write-Verbose "Ending function   : Start-App"
    } else {
        Write-Verbose "Function: Start-App, app has focus."
    }
}

function Invoke-LoadQRModule {
    # Source for this code: https://github.com/TobiasPSP/Modules.QRCodeGenerator 
    Write-Verbose "Starting function : Invoke-LoadQRModule, Loading QR Imaging Module"
    try {
        # Version: 2.4.1
        # loading binaries from string
        $content = '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ggAAAAJQbzQAAAYREG8oAAAKEREcWG8pAAAKLGkCUG80AAAGERBvKAAAChERHVhvKQAACi1QAlBvNAAABhEQbygAAAoRER5YbykAAAotNwJQbzQAAAYREG8oAAAKEREfCVhvKQAACi0dAlBvNAAABhEQbygAAAoRER8KWG8pAAAKOSUBAAACUG80AAAGERBvKAAAChERbykAAAo6EAEAAAJQbzQAAAYREG8oAAAKEREXWG8pAAAKOvQAAAACUG80AAAGERBvKAAAChERGFhvKQAACjrYAAAAAlBvNAAABhEQbygAAAoRERlYbykAAAo6vAAAAAJQbzQAAAYREG8oAAAKEREaWG8pAAAKOaAAAAACUG80AAAGERBvKAAAChERG1hvKQAACjqEAAAAAlBvNAAABhEQbygAAAoRERxYbykAAAosawJQbzQAAAYREG8oAAAKEREdWG8pAAAKLFICUG80AAAGERBvKAAAChERHlhvKQAACiw5AlBvNAAABhEQbygAAAoRER8JWG8pAAAKLR8CUG80AAAGERBvKAAAChERHwpYbykAAAosBQgfKFgMAlBvNAAABhERbygAAAoREG8pAAAKOQ4BAAACUG80AAAGEREXWG8oAAAKERBvKQAACjryAAAAAlBvNAAABhERGFhvKAAAChEQbykAAAo51gAAAAJQbzQAAAYRERlYbygAAAoREG8pAAAKOboAAAACUG80AAAGEREaWG8oAAAKERBvKQAACjmeAAAAAlBvNAAABhERG1hvKAAAChEQbykAAAo6ggAAAAJQbzQAAAYRERxYbygAAAoREG8pAAAKLGkCUG80AAAGEREdWG8oAAAKERBvKQAACi1QAlBvNAAABhERHlhvKAAAChEQbykAAAotNwJQbzQAAAYRER8JWG8oAAAKERBvKQAACi0dAlBvNAAABhERHwpYbygAAAoREG8pAAAKOSUBAAACUG80AAAGERFvKAAAChEQbykAAAo6EAEAAAJQbzQAAAYRERdYbygAAAoREG8pAAAKOvQAAAACUG80AAAGEREYWG8oAAAKERBvKQAACjrYAAAAAlBvNAAABhERGVhvKAAAChEQbykAAAo6vAAAAAJQbzQAAAYRERpYbygAAAoREG8pAAAKOaAAAAACUG80AAAGEREbWG8oAAAKERBvKQAACjqEAAAAAlBvNAAABhERHFhvKAAAChEQbykAAAosawJQbzQAAAYRER1YbygAAAoREG8pAAAKLFICUG80AAAGEREeWG8oAAAKERBvKQAACiw5AlBvNAAABhERHwlYbygAAAoREG8pAAAKLR8CUG80AAAGEREfClhvKAAAChEQbykAAAosBQgfKFgMEREXWBMRERERBB8KWT9K+///ERAXWBMQERARBD8z+///IwAAAAAAAAAAEwUCUG80AAAGb2AAAAoTEitMEhIoYQAACm9iAAAKExMrHBETb2MAAAqlQQAAASwOEQUjAAAAAAAA8D9YEwURE29lAAAKLdveFRETdRUAAAETFBEULAcRFG9IAAAK3BISKGYAAAotq94OEhL+Fg8AABtvSAAACtwRBQJQbzQAAAZvJgAACgJQbzQAAAZvJgAAClpsWyMAAAAAAABZQFolIwAAAAAAABRAWyiwAAAKaRtaHzJZKDMBAAobWxMGIwAAAAAAABRAWyiwAAAKaRtaHy1ZKDMBAAobWxMHEQYRByhtAAAKHwpaDQYHWAhYCVgqARwAAAIA1AYp/QYVAAAAAAIAxAZZHQcOAAAAAEJTSkIBAAEAAAAAAAwAAAB2NC4wLjMwMzE5AAAAAAUAbAAAALxKAAAjfgAAKEsAAJQxAAAjU3RyaW5ncwAAAAC8fAAAzDMAACNVUwCIsAAAEAAAACNHVUlEAAAAmLAAAHAZAAAjQmxvYgAAAAAAAAACAAABV5+iKQkOAAAA+gEzABYAAAEAAABRAAAAYwAAABICAAA5AQAArAEAAAYAAAAzAQAAawEAAJAAAAALAAAAVQAAABEAAAAzAAAAPwAAAE0AAAATAAAAAQAAAAwAAABVAAAABgAAACoAAAAAAAwiAQAAAAAABgCgHVkqBgAhHlkqBgCPHD4pDwB5KgAABgDSHMokBgCDHcokBgBkHcokBgAIHsokBgDAHcokBgDZHcokBgD7HMokBgC+HDoqCgCBHDoqBgBHHcokBgAWHYofBgBmHFkqBgA8LWsiDgAiHD4pDgCjHD4pDgAvHT4pBgA8GWsiEgBWBGURBgCeJ+EvBgDvA2URFgB4H+EvBgA7I2siBgDkA2siBgA1GmsiBgBCBmURBgAvBmsiBgB7IWsiBgDMJWsiBgDpHGsiEgBRBmUREgD8MBMsGgA5IvMNBgD0HWsiGgA/IvMNHgAgIhckEgAeBGURHgAuIhckWwBiKAAABgBTKBMsBgBHBGURIgA3JsokBgC6GmsiBgCFB2siJgA2BrEmBgBVBGUREgA0BGURBgByIGsiBgCDJ2siBgBlHmsiBgCLLFkqBgD/MGsiBgBbGWsiJgAxGbEmKgBOJqMkBgCXKqMkBgALJ2siLgBxMNorBgARBWsiMgBaL2siHgDJFxckBgBeI2siMgCxIGsiBgASBGsiJgD9A7EmBgAnIWsiBgBUGWsiMgCOLmsiBgBPJWsiBgAIBWsiBgAwGRMsBgBYG2siBgBuGWsiIgDCK8okIgBFJsokIgBmJsokIgCgG8okBgAmBGURAAAAAO8KAAAAAAEAAQAAARAA7QUAAEUAAQABAAABEAADBgAARQADAAcAAAEQABkGAABFAAUADQCBABAAUBesJ0UABwATAAEAEABEF6wnFAAIABkAAQAQADMXrCcUAAgAHwCAARAAZSmsJ0UACAAmAIEBEABtKKwnRQAIACkAAQEQACUXrCcUAAgALwABABAA8g+sJ0UACAA0AAEAEAB+KKwnRQAKAD0AAAAQAJIpdSlFABUAZAAAAQAA+AoAAEUAFQBmAAIAEAAcIQAARQAoAGYAAgAQAO0hAABFACwAaAACABAA7A4AAEUAMABsAAIAEADoDgAARQAzAG8AAgAQADwkAABFADYAcgACABAAEycAAEUAOQB0AAIAEAACIgAARQA6AHYAAgAQABgiAABFADsAeAACABAAQBgAAEUAPAB6AAIAEABVIQAARQA9AHwAAgAQABsQAABFAD8AfgACABAArCwAAEUATwCAAAIAEACUFwAARQBTAIIAAgAQAPkXAABFAF4AhAACABAAdBcAAEUAaQCGAAIAEADxLgAARQB8AIsAAgAQAJ4WAABFAIIAjQACABAAzB4AAEUAigCiAAIAEAC4JAAARQCRAKQAAwEQAJMnAABFAJYApgACAQAAISQAAGkAngC0AIMBEABqJwAARQCiALQAAgEAAKchAABpAKIAwgADAQAArxcAAGkApwDCAAsBEAADJgAAuQCtAMIACwEQACshAAC5AK8AwgALARAAJyYAALkAtgDKAAsBEABaJgAAuQC+ANMACwEQADsrAAC5AMAA1gALARAAiCAAALkAwgDZAAsBEABfIgAAuQDEANwAAwAQAAAjAABFAMYA3wADABAA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ZVNpemU9MjQwAF9fU3RhdGljQXJyYXlJbml0VHlwZVNpemU9Mzg0MABfX1N0YXRpY0FycmF5SW5pdFR5cGVTaXplPTQwAF9fU3RhdGljQXJyYXlJbml0VHlwZVNpemU9MTYwAF9fU3RhdGljQXJyYXlJbml0VHlwZVNpemU9MjU2MABfX1N0YXRpY0FycmF5SW5pdFR5cGVTaXplPTkwADw+Y19fRGlzcGxheUNsYXNzNDBfMAA8PmNfX0Rpc3BsYXlDbGFzczEyXzAAPD45X180Ml8wADxDcmVhdGVBbHBoYW51bUVuY0RpY3Q+Yl9fNDJfMAA8PjlfXzIzXzAAPEJpbmFyeVN0cmluZ1RvQml0QmxvY2tMaXN0PmJfXzIzXzAAPEJpbmFyeVN0cmluZ0xpc3RUb0RlY0xpc3Q+Yl9fMjRfMAA8PjlfXzVfMAA8VG9TdHJpbmc+Yl9fNV8wADw+OV9fMTZfMAA8Q2FsY3VsYXRlRUNDV29yZHM+Yl9fMTZfMAA8PjlfXzM4XzAAPE11bHRpcGx5QWxwaGFQb2x5bm9tcz5iX18zOF8wADw+Y19fRGlzcGxheUNsYXNzMzhfMAA8PmNfX0Rpc3BsYXlDbGFzczE5XzAAPD5jX19EaXNwbGF5Q2xhc3MzOV8wADxDcmVhdGVRckNvZGU+Yl9fMAA8R2V0QWxwaGFFeHBGcm9tSW50VmFsPmJfXzAAPEdldFZlcnNpb24+Yl9fMAA8R2V0SW50VmFsRnJvbUFscGhhRXhwPmJfXzAAVkNhcmQyMQBTSEExADw+OV9fNDBfMQA8R2V0QWxwaGFFeHBGcm9tSW50VmFsPmJfXzQwXzEAPD45X18yM18xADxCaW5hcnlTdHJpbmdUb0JpdEJsb2NrTGlzdD5iX18yM18xADw+OV9fNV8xADxUb1N0cmluZz5iX181XzEAPD45X18zOF8xADxNdWx0aXBseUFscGhhUG9seW5vbXM+Yl9fMzhfMQA8PmNfX0Rpc3BsYXlDbGFzczM4XzEAPD45X18zOV8xADxHZXRJbnRWYWxGcm9tQWxwaGFFeHA+Yl9fMzlfMQBJU09fODg1OV8xADw+OV9fMQA8Q3JlYXRlUXJDb2RlPmJfXzEAPEdldFZlcnNpb24+Yl9fMQBOdWxsYWJsZWAxAElFbnVtZXJhYmxlYDEASU9yZGVyZWRFbnVtZXJhYmxlYDEAUHJlZGljYXRlYDEAUXVldWVgMQBJQ29sbGVjdGlvbmAxAEVxdWFsaXR5Q29tcGFyZXJgMQBJRW51bWVyYXRvcmAxAElMaXN0YDEAQWVzMTkyQ2ZiMQBBZXMyNTZDZmIxAEFlczEyOENmYjEAYWx0ZXJuYXRpdmVQcm9jZWR1cmUxAFZlcnNpb24xAFBhdHRlcm4xAGdldF9Db2Rld29yZHNJbkdyb3VwMQBjb2Rld29yZHNJbkdyb3VwMQBnZXRfQmxvY2tzSW5Hcm91cDEAYmxvY2tzSW5Hcm91cDEAcjEAU0hBNTEyAENyYzMyAEFkbGVyMzIAVUludDMyAFRvSW50MzIAQ0FEODYyMzgzODI3NDc0MEQ2NDk3NDg5RjU0N0NFOTcyQzQyQTk0MgA8PjlfXzEyXzIAPENyZWF0ZVFyQ29kZT5iX18xMl8yADw+OV9fMjNfMgA8QmluYXJ5U3RyaW5nVG9CaXRCbG9ja0xpc3Q+Yl9fMjNfMgA8PjlfXzVfMgA8VG9TdHJpbmc+Yl9fNV8yADw+OV9fMzhfMgA8TXVsdGlwbHlBbHBoYVBvbHlub21zPmJfXzM4XzIASVNPXzg4NTlfMgA8R2V0VmVyc2lvbj5iX18yADw+Zl9fQW5vbnltb3VzVHlwZTBgMgA8PmZfX0Fub255bW91c1R5cGUxYDIAPD5mX19Bbm9ueW1vdXNUeXBlMmAyAEZ1bmNgMgBJR3JvdXBpbmdgMgBLZXlWYWx1ZVBhaXJgMgBEaWN0aW9uYXJ5YDIAYWx0ZXJuYXRpdmVQcm9jZWR1cmUyAFZlcnNpb24yAFBhdHRlcm4yAGdldF9Db2Rld29yZHNJbkdyb3VwMgBjb2Rld29yZHNJbkdyb3VwMgBnZXRfQmxvY2tzSW5Hcm91cDIAYmxvY2tzSW5Hcm91cDIAcjIAY29udGFjdF92MgAzNzNCNDk0RjIxMEM2NTYxMzRDNTcyOEQ1NTFENEM5N0IwMTNFQjMzAF9fU3RhdGljQXJyYXlJbml0VHlwZVNpemU9MwA8PjlfXzIzXzMAPEJpbmFyeVN0cmluZ1RvQml0QmxvY2tMaXN0PmJfXzIzXzMAPD45X18zADxHZXRWZXJzaW9uPmJfXzMAPE11bHRpcGx5QWxwaGFQb2x5bm9tcz5iX18zAEZ1bmNgMwBWQ2FyZDMAUGF0dGVybjMAX19TdGF0aWNBcnJheUluaXRUeXBlU2l6ZT0xMDI0ADYyQjc5MkQ2MDNBOTAzMjQ3MEY2NjA2OEVCREQ0QzJDMjdCQzM1ODQAPE11bHRpcGx5QWxwaGFQb2x5bm9tcz5iX18zOF80ADw+OV9fMTlfNAA8R2V0VmVyc2lvbj5iX18xOV80AElTT184ODU5XzQAUmM0AFZDYXJkNABQYXR0ZXJuNAA0Q0FFQ0U1MzlCMDM5QjE2RTE2MjA2RUEyNDc4RjhDNUZGQjJDQTA1AElTT184ODU5XzE1ADdDNjc1OEE2RTE4M0VBMTdDRjEzMEYxREJDRTlBMjVCM0NBQjJFOTUAOTZBQjNBNjQ1QzAwRkEzRTZDNUExODAyQjI0MzNDOUVGRDdFMjNGNQBJU09fODg1OV81ADxNdWx0aXBseUFscGhhUG9seW5vbXM+Yl9fNQBSYzRNZDUAUGF0dGVybjUAU0hBMjU2AEVGMkYzMjVBQTk2RDAyMkUxQzNDMTZBMDcxNDE2RjMzQjg4NEEwRTYAOUI2OTcwNTg3RkI3NERDQjM5NDNCOTlBQzNGNjAxNTlCRTIyQUJFNgA8PjlfXzM4XzYAPE11bHRpcGx5QWxwaGFQb2x5bm9tcz5iX18zOF82AFBhdHRlcm42ADlBRTJBODZCNjJCRkYxMzJBRkI5NzUxQzdBODZGRUEyNUM0ODgyMDcASVNPXzg4NTlfNwBQYXR0ZXJuNwBfX1N0YXRpY0FycmF5SW5pdFR5cGVTaXplPTE4AEM4RDYyQjI5NzM3QTBDODg2NTM3NTY0ODA2Q0RFQ0YwNEE1NzFDQjgAZ2V0X1VURjgAVVRGXzgAQWVzMTkyQ2ZiOABBZXMyNTZDZmI4AEFlczEyOENmYjgAZm9yY2VVdGY4AElzVXRmOABQYXR0ZXJuOAAwRDQ1QzUzMDk0QTUyRDgzNzI3QTI5NTQ2QjU5OTk3MDMyMEQ0QjE5ADQxQTI0NjM4M0UwQUEwNTM5NDE4Q0QyMUE3QzUyMkRFMjg5OEZDMjkAQ3JlZGl0b3JSZWZlcmVuY2VJc28xMTY0OQA8PjkANzg2NzBFODhBOUMyQzcxMTEyNDQ3MUQyRjI0QThEQkM4Q0U1REJBOQA8TW9kdWxlPgA8UHJpdmF0ZUltcGxlbWVudGF0aW9uRGV0YWlscz4AWEJBAE1HQQBBT0EAV1BBAFhVQQBFOEI5Qzc3N0RFQkVFMjk1NzE2N0RCQkRGQTQ3OTA0ODlGQjA3NjFCAFBBQgBYQkIAOThEQ0Q5MEQ0RUU2MzJCNjk4OEE3MkM1QzdDRjI0NkIxMUQxRjlEQgBUSEIAQk9CAEVUQgBSVUIARTg0Q0Y3NTAzMzdCQjcwMTE0QTc2QTY0QTYyRDE2M0IyQTc5Q0UzQwBYQkMAQ1JDAENVQwBTVkMAQ0FEAE1BRABOQUQAQkJEAFNCRABYQkQAWENEAEFFRABTR0QAQkhEAGlzSGlkZGVuU1NJRABGSkQASEtEAE1LRABBTUQAQk1EAEdNRABKTUQAQk5EAElFTkQAVE5EAFZORABKT0QAWFBEAElRRABMUkQAU1JEAEJTRABSU0QAVVNEAFNURABUVEQAQVVEAEtXRABUV0QAR1lEAEtZRABMWUQAQlpEAERaRABOWkQAQ0hFAFBMVEUAQ1ZFADQ3RTNCODI2NUYzQTlCRDE2MkE2Njc3RjNDRDQ2RjY1Qzc1QzZBQUYAWEFGADk3NDAyQTYzN0MyRTVFNDgwNjM1N0UwQUVDQzEyNDZCODFFNUYwREYAQ0RGADFCQUU2MERDMjhEMzY1QjVFRjU0OTM0OTg3ODcwNzhCRjUzRDIwRUYAVkVGAENIRgBCSUYAREpGAENMRgBLTUYAR05GAFhPRgBYUEYASFVGAFJXRgBYQUcAU0RHAEFORwBNQVRNU0cASFRHAEFXRwBQWUcAVUFIAEVDSQBVWUkATEFLAFNFSwBQR0sAREtLAE1NSwBOT0sASFJLAElTSwBNV0sAQ1pLAE1ETABHRUwAQUxMAFNMTABITkwAQlJMAExTTABaV0wAU1pMAEJBTQB1dGY4Qk9NAFBFTgBBRk4AQkdOAE5HTgBQTE4ATk9OAFJPTgBFUk4AVVNOAEJUTgBNWE4AQVpOAE1aTgBHRU8AU3lzdGVtLklPAE5JTwBNUk8ASXNWYWxpZElTTwBNQUlMVE8ATU1TVE8AU01TVE8AR0JQAExCUABXRVAARUdQAFBIUABTSFAAR0lQAEZLUABDTFAAQ09QAERPUABNT1AAVE9QAFNTUABTTVRQAEhPVFAAVE9UUABDVVAAQldQAFNZUABHVFEAUUFSAFNBUgBaQVIAU0NSAElIRFIASURSAFhEUgBZRVIAS0hSAExLUgBQS1IAT01SAElOUgBTQ09SAE5QUgBJUlIAUVJSAEVVUgBNVVIATVZSAEJZUgBNWVIAS0VTAEtHUwBHSFMAVEpTAElMUwBNTVMAU01TAHRSTlMAU09TAFNNU19pT1MAQVJTAFhUUwBUWlMAVVpTAElEQVQAQkRUAFRNVABNTlQAWFBUAFdTVABLWlQAWEFVAENPVQBYU1UAVVlVAEJPVgBWVVYATVhWAENIVwBaTVcAS1BXAEtSVwBVR1gAWFhYAGdldF9YAENOWQBKUFkAVFJZAGdldF9ZAHZhbHVlX18AZGFya0NvbG9yUmdiYQBsaWdodENvbG9yUmdiYQBnZXRfRXhwb25lbnRBbHBoYQBleHBvbmVudEFscGhhAHNpbmdsZWRpcmVjdGRlYml0c2VwYQBwZXJpb2RpY3NpbmdsZXBheW1lbnRzZXBhAFNldFFSQ29kZURhdGEAZ2V0X1FyQ29kZURhdGEAc2V0X1FyQ29kZURhdGEAQ29udGFjdERhdGEAR2V0UmF3RGF0YQByYXdEYXRhAGRhdGEAQWVzMjU2Q2IAQ2FtZWxsaWExOTJDZmIAQWVzMTkyQ2ZiAFJjMkNmYgBDYXN0NUNmYgBDYW1lbGxpYTI1NkNmYgBDYW1lbGxpYTEyOENmYgBBZXMxMjhDZmIASWRlYUNmYgBTZWVkQ2ZiAEJmQ2ZiAERlc0NmYgBBZXMxOTJPZmIAQWVzMjU2T2ZiAEFlczEyOE9mYgBkYXJrQ29sb3JSZ2IAbGlnaHRDb2xvclJnYgBzYgA8PmMAQmluVG9EZWMASXNWYWxpZEJpYwBiaWMAR2V0TGluZUJ5TGluZUdyYXBoaWMAR2V0R3JhcGhpYwBQbGFpblRleHRUb0JpbmFyeU51bWVyaWMAUGxhaW5UZXh0VG9CaW5hcnlBbHBoYW51bWVyaWMAU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMAYm5jAG1hbmRhdGVJZABjcmVkaXRvcklkAHR4UGF5bWVudElkAFJlYWQAQWRkAElzQmxvY2tlZABTdHJ1Y3R1cmVkAFVuc3RydWN0dXJlZABVbmNvbXByZXNzZWQASW5kZXhlZABpc0hpZGRlblNzaWQAc3NpZABwb2x5bm9tT2xkADxWYWx1ZT5pX19GaWVsZAA8dmVyc2lvbj5pX19GaWVsZAA8Q2hyPmlfX0ZpZWxkADxJbmRleD5pX19GaWVsZAA8Y2FwYWNpdHk+aV9fRmllbGQAPENvZGV3b3Jkc0luR3JvdXAxPmtfX0JhY2tpbmdGaWVsZAA8QmxvY2tzSW5Hcm91cDE+a19fQmFja2luZ0ZpZWxkADxDb2Rld29yZHNJbkdyb3VwMj5rX19CYWNraW5nRmllbGQAPEJsb2Nrc0luR3JvdXAyPmtfX0JhY2tpbmdGaWVsZAA8WD5rX19CYWNraW5nRmllbGQAPFk+a19fQmFja2luZ0ZpZWxkADxFeHBvbmVudEFscGhhPmtfX0JhY2tpbmdGaWVsZAA8UXJDb2RlRGF0YT5rX19CYWNraW5nRmllbGQAPFBlcmlvZD5rX19CYWNraW5nRmllbGQAPFR5cGU+a19fQmFja2luZ0ZpZWxkADxJbnRlZ2VyVmFsdWU+a19fQmFja2luZ0ZpZWxkADxCaXRTdHJpbmc+a19fQmFja2luZ0ZpZWxkADxXaWR0aD5rX19CYWNraW5nRmllbGQAPEVDQ1BlckJsb2NrPmtfX0JhY2tpbmdGaWVsZAA8TGFiZWw+a19fQmFja2luZ0ZpZWxkADxFcnJvckNvcnJlY3Rpb25MZXZlbD5rX19CYWNraW5nRmllbGQAPEFsZ29yaXRobT5rX19CYWNraW5nRmllbGQAPFZlcnNpb24+a19fQmFja2luZ0ZpZWxkADxCbG9ja051bWJlcj5rX19CYWNraW5nRmllbGQAPEdyb3VwTnVtYmVyPmtfX0JhY2tpbmdGaWVsZAA8Q291bnRlcj5rX19CYWNraW5nRmllbGQAPElzc3Vlcj5rX19CYWNraW5nRmllbGQAPEVDQ1dvcmRzPmtfX0JhY2tpbmdGaWVsZAA8Q29kZVdvcmRzPmtfX0JhY2tpbmdGaWVsZAA8VG90YWxEYXRhQ29kZXdvcmRzPmtfX0JhY2tpbmdGaWVsZAA8RGV0YWlscz5rX19CYWNraW5nRmllbGQAPFBvbHlJdGVtcz5rX19CYWNraW5nRmllbGQAPERpZ2l0cz5rX19CYWNraW5nRmllbGQAPENhcGFjaXR5RGljdD5rX19CYWNraW5nRmllbGQAPFNlY3JldD5rX19CYWNraW5nRmllbGQAPEhlaWdodD5rX19CYWNraW5nRmllbGQAPEVDQ1dvcmRzSW50PmtfX0JhY2tpbmdGaWVsZAA8Q29kZVdvcmRzSW50PmtfX0JhY2tpbmdGaWVsZAA8Q29lZmZpY2llbnQ+a19fQmFja2luZ0ZpZWxkADxFeHBvbmVudD5rX19CYWNraW5nRmllbGQAPE1vZHVsZU1hdHJpeD5rX19CYWNraW5nRmllbGQAZ2Fsb2lzRmllbGQAV3JpdGVFbmQAV3JpdGVDaHVua0VuZABUcmltRW5kAEFwcGVuZABHZXREZWNsYXJlZE1ldGhvZABtZXRob2QAZ2V0X1BlcmlvZABzZXRfUGVyaW9kAE1lQ2FyZABPbmVUaW1lUGFzc3dvcmQAcGFzc3dvcmQAUmVwbGFjZQBJc051bGxPcldoaXRlU3BhY2UASXNXaGl0ZVNwYWNlAFR5cGVPZlJlbWl0dGFuY2UAdHlwZU9mUmVtaXR0YW5jZQBzZXBhUmVmZXJlbmNlAFFyUmVmZXJlbmNlAHJlZmVyZW5jZQBQbmdCeXRlUVJDb2RlAEJpdG1hcEJ5dGVRUkNvZGUAQXNjaWlRUkNvZGUAQWJzdHJhY3RRUkNvZGUAR2V0SGFzaENvZGUATWFza0NvZGUAQmV6YWhsQ29kZQB6aXBDb2RlAENyZWF0ZVFyQ29kZQBTd2lzc1FyQ29kZQBxckNvZGUAZW5jTW9kZQBFbmNvZGluZ01vZGUAaW50ZXJuYWxNb2RlAENvbXByZXNzaW9uTW9kZQBhdXRoZW50aWNhdGlvbk1vZGUAY29tcHJlc3NNb2RlAEdpcm9jb2RlAGxvbmdpdHVkZQBsYXRpdHVkZQB1bnN0cnVjdHVyZWRNZXNzYWdlAGdldF9VbnN0cnVjdHVyZU1lc3NhZ2UAV2hhdHNBcHBNZXNzYWdlAG1lc3NhZ2UAQWRkUmFuZ2UAUmVtb3ZlUmFuZ2UASW52b2tlAEdyZXlzY2FsZQBDcmVhdGVDYXBhY2l0eUVDQ1RhYmxlAGNhcGFjaXR5RUNDVGFibGUAYWxwaGFudW1FbmNUYWJsZQBDcmNUYWJsZQBDcmVhdGVBbnRpbG9nVGFibGUAbnVtVGFibGUAQ3JlYXRlQWxpZ25tZW50UGF0dGVyblRhYmxlAGFsaWdubWVudFBhdHRlcm5UYWJsZQBDcmVhdGVDYXBhY2l0eVRhYmxlAGNhcGFjaXR5VGFibGUASUVudW1lcmFibGUASURpc3Bvc2FibGUAR2V0UHJlYW1ibGUARG91YmxlAFJ1bnRpbWVGaWVsZEhhbmRsZQBSdW50aW1lVHlwZUhhbmRsZQBHZXRUeXBlRnJvbUhhbmRsZQBSZWN0YW5nbGUAU2luZ2xlAHNpbXBsZQB0aXRsZQBQbGFjZURhcmtNb2R1bGUAcGl4ZWxzUGVyTW9kdWxlAHJlcGVhdFBlck1vZHVsZQBpc0hleFN0eWxlAGdldF9OYW1lAHJlY2lwaWVudE5hbWUAbmlja25hbWUAc2t5cGVVc2VybmFtZQBsYXN0bmFtZQBob3N0bmFtZQBmaXJzdG5hbWUARGF0ZVRpbWUAU3lzdGVtLlJ1bnRpbWUAZW5kT2ZMaW5lAGdldF9OZXdMaW5lAEFkZFF1aWV0Wm9uZQBtb2JpbGVQaG9uZQB3b3JrUGhvbmUAcGhvbmUAZ2V0X1R5cGUAc2V0X1R5cGUAUmVmZXJlbmNlVHlwZQByZWZlcmVuY2VUeXBlAFZhbHVlVHlwZQBnZXRfUmVmVHlwZQBPbmVUaW1lUGFzc3dvcmRBdXRoVHlwZQBJYmFuVHlwZQBpYmFuVHlwZQBDb2xvclR5cGUAY29sb3JUeXBlAENvbnRhY3RPdXRwdXRUeXBlAG91dHB1dFR5cGUAUmVmZXJlbmNlVGV4dFR5cGUAcmVmZXJlbmNlVGV4dFR5cGUAQXV0aG9yaXR5VHlwZQB0eXBlAFdoZXJlAFNjb3JlAGRhdGVPZlNpZ25hdHVyZQBQbmdTaWduYXR1cmUAZ2V0X0ludmFyaWFudEN1bHR1cmUATWV0aG9kQmFzZQBwb2x5bm9tQmFzZQBEaXNwb3NlAFBhcnNlAFJldmVyc2UAcGVyaW9kaWNMYXN0RXhlY3V0aW9uRGF0ZQBwZXJpb2RpY0ZpcnN0RXhlY3V0aW9uRGF0ZQBleGVjdXRpb25EYXRlAEFnZ3JlZ2F0ZQBEZWZsYXRlAERlYnVnZ2VyQnJvd3NhYmxlU3RhdGUAaUNhbENvbXBsZXRlAFdyaXRlAHdlYnNpdGUAbm90ZQBXcml0ZVBhbGV0dGUAQ29tcGlsZXJHZW5lcmF0ZWRBdHRyaWJ1dGUAR3VpZEF0dHJpYnV0ZQBEZWJ1Z2dhYmxlQXR0cmlidXRlAERlYnVnZ2VyQnJvd3NhYmxlQXR0cmlidXRlAENvbVZpc2libGVBdHRyaWJ1dGUAQXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBPYnNvbGV0ZUF0dHJpYnV0ZQBBc3NlbWJseVRyYWRlbWFya0F0dHJpYnV0ZQBUYXJnZXRGcmFtZXdvcmtBdHRyaWJ1dGUARGVidWdnZXJIaWRkZW5BdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAEFzc2VtYmx5UHJvZHVjdEF0dHJpYnV0ZQBBc3NlbWJseUNvcHlyaWdodEF0dHJpYnV0ZQBQYXJhbUFycmF5QXR0cmlidXRlAEFzc2VtYmx5Q29tcGFueUF0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBJbnRUbzRCeXRlAFdyaXRlQnl0ZQBQbGFpblRleHRUb0JpbmFyeUJ5dGUARGVxdWV1ZQBFbnF1ZXVlAHRvR2x1ZQBnZXRfVmFsdWUAZ2V0X0ludGVnZXJWYWx1ZQBpbnRlZ2VyVmFsdWUAZ2V0X0hhc1ZhbHVlAHZhbHVlAFJlbW92ZQBzaXplAHRhZwBTaGFkb3dTb2Nrc0NvbmZpZwBPcmRlckJ5RGVzY2VuZGluZwBTeXN0ZW0uVGV4dC5FbmNvZGluZwBNTVNFbmNvZGluZwBTTVNFbmNvZGluZwBHaXJvY29kZUVuY29kaW5nAE1haWxFbmNvZGluZwBHZW9sb2NhdGlvbkVuY29kaW5nAENvbnZlcnRTdHJpbmdUb0VuY29kaW5nAEdldEVuY29kaW5nAEV2ZW50RW5jb2RpbmcAZW5jb2RpbmcAU3lzdGVtLlJ1bnRpbWUuVmVyc2lvbmluZwBUb0Jhc2U2NFN0cmluZwBFc2NhcGVEYXRhU3RyaW5nAHdoaXRlU3BhY2VTdHJpbmcAUmV2ZXJzZVN0cmluZwBFc2NhcGVVcmlTdHJpbmcAR2V0VmVyc2lvblN0cmluZwBITUFDVG9TdHJpbmcAVGltZVRvU3RyaW5nAGRhcmtDb2xvclN0cmluZwBjb2xvclN0cmluZwBHZXRGb3JtYXRTdHJpbmcAR2V0U3RyaW5nAGdldF9CaXRTdHJpbmcAYml0U3RyaW5nAGJpbmFyeVN0cmluZwBTdWJzdHJpbmcAYWxvZwBBbnRpbG9nAFN5c3RlbS5EaWFnbm9zdGljcy5EZWJ1ZwBJc01hdGNoAE1hdGgAZ2V0X1dpZHRoAHdpZHRoAGdldF9MZW5ndGgAR2V0RGF0YUxlbmd0aABHZXRDb3VudEluZGljYXRvckxlbmd0aABTZXRMZW5ndGgAbGVuZ3RoAFN0YXJ0c1dpdGgAYml0RGVwdGgAV2lGaQBLYW5qaQBVcmkAQ29kZXdvcmRCbG9jawBnZXRfRUNDUGVyQmxvY2sAZWNjUGVyQmxvY2sAQm9va21hcmsAR2V0QWxwaGFFeHBGcm9tSW50VmFsAGludFZhbABEZWNpbWFsAFVuaXZlcnNhbABnZXRfTGFiZWwAc2V0X0xhYmVsAGxhYmVsAEVDQ0xldmVsAGVjY0xldmVsAGdldF9FcnJvckNvcnJlY3Rpb25MZXZlbABlcnJvckNvcnJlY3Rpb25MZXZlbABsZXZlbABNYWlsAGVtYWlsAFJlbW92ZUFsbABTa3lwZUNhbGwAUVJDb2Rlci5kbGwAVXJsAHVybABEZWZsYXRlU3RyZWFtAEdaaXBTdHJlYW0ATWVtb3J5U3RyZWFtAHN0cmVhbQBnZXRfSXRlbQBzZXRfSXRlbQBQb2x5bm9tSXRlbQBTeXN0ZW0AZ2V0X0FsZ29yaXRobQBzZXRfQWxnb3JpdGhtAE9vbmVUaW1lUGFzc3dvcmRBdXRoQWxnb3JpdGhtAFRyaW0AQ2FsY3VsYXRlTWVzc2FnZVBvbHlub20AbWVzc2FnZVBvbHlub20AZ2VuUG9seW5vbQBDYWxjdWxhdGVHZW5lcmF0b3JQb2x5bm9tAHJlc1BvbHlub20AbGVhZFRlcm0ATXVsdGlwbHlHZW5lcmF0b3JQb2x5bm9tQnlMZWFkdGVybQBkZWNOdW0ARW51bQBJc1ZhbGlkSWJhbgBnZXRfSXNRckliYW4AaWJhbgBCb29sZWFuAG9wX0dyZWF0ZXJUaGFuAG9wX0xlc3NUaGFuAFdyaXRlSW50QmlnRW5kaWFuAERlY1RvQmluAE1pbgBKb2luAGdldF9WZXJzaW9uAHNldF9WZXJzaW9uAFBsYWNlVmVyc2lvbgBHaXJvY29kZVZlcnNpb24AbWFza1ZlcnNpb24ATW9kdWxlc1BlclNpZGVGcm9tVmVyc2lvbgBHZXRWZXJzaW9uAGdldF92ZXJzaW9uAFN5c3RlbS5JTy5Db21wcmVzc2lvbgBBdXRoZW50aWNhdGlvbgBHZW9sb2NhdGlvbgByZW1pdHRhbmNlSW5mb3JtYXRpb24AQ29udmVydFRvQWxwaGFOb3RhdGlvbgBDb252ZXJ0VG9EZWNOb3RhdGlvbgBwZXJpb2RpY1RpbWV1bml0Um90YXRpb24AU3lzdGVtLkdsb2JhbGl6YXRpb24ATW9uZXJvVHJhbnNhY3Rpb24AU3lzdGVtLlJlZmxlY3Rpb24AZ2V0X1Bvc2l0aW9uAHNldF9Qb3NpdGlvbgBTd2lzc1FyQ29kZVJlZmVyZW5jZUV4Y2VwdGlvbgBCZXphaGxDb2RlRXhjZXB0aW9uAFN3aXNzUXJDb2RlRXhjZXB0aW9uAEdpcm9jb2RlRXhjZXB0aW9uAEFyZ3VtZW50T3V0T2ZSYW5nZUV4Y2VwdGlvbgBTaGFkb3dTb2Nrc0NvbmZpZ0V4Y2VwdGlvbgBTd2lzc1FyQ29kZUliYW5FeGNlcHRpb24ATW9uZXJvVHJhbnNhY3Rpb25FeGNlcHRpb24AU3dpc3NRckNvZGVDb250YWN0RXhjZXB0aW9uAHR4RGVzY3JpcHRpb24AZGVzY3JpcHRpb24AcmVhc29uAE1hc2tQYXR0ZXJuAEFsaWdubWVudFBhdHRlcm4AcGFkTGVmdFVwVG8AQ29weVRvAEVDQ0luZm8AZWNjSW5mbwBNZXRob2RJbmZvAEdldFR5cGVJbmZvAEN1bHR1cmVJbmZvAFZlcnNpb25JbmZvAE1lbWJlckluZm8AWmVybwBHWmlwAGlucABTaHJpbmtBbHBoYUV4cABHZXRJbnRWYWxGcm9tQWxwaGFFeHAAYWxwaGFFeHAAZXhwAFN5c3RlbS5MaW5xADxWYWx1ZT5qX19UUGFyADx2ZXJzaW9uPmpfX1RQYXIAPENocj5qX19UUGFyADxJbmRleD5qX19UUGFyADxjYXBhY2l0eT5qX19UUGFyAENoYXIAYnIAUGhvbmVOdW1iZXIAaG91c2VOdW1iZXIAZ2V0X0Jsb2NrTnVtYmVyAGJsb2NrTnVtYmVyAGdldF9Hcm91cE51bWJlcgBncm91cE51bWJlcgBudW1iZXIATW9kdWxlUGxhY2VyAFdyaXRlSGVhZGVyAElGb3JtYXRQcm92aWRlcgBQbmdCdWlsZGVyAFN0cmluZ0J1aWxkZXIAUVJDb2RlcgBwdXJwb3NlT2ZDcmVkaXRUcmFuc2ZlcgBwb2x5bm9tTXVsdGlwbGllcgBpbm5lcgBUb1VwcGVyAG1lc3NhZ2VUb0dpcm9jb2RlVXNlcgBnZXRfQ291bnRlcgBzZXRfQ291bnRlcgBnZXRfSXNzdWVyAHNldF9Jc3N1ZXIAbWFpbFJlY2VpdmVyAGdldF9DaHIAa2V5UGFpcgBGbG9vcgBJRW51bWVyYXRvcgBHZXRFbnVtZXJhdG9yAFBheWxvYWRHZW5lcmF0b3IAUVJDb2RlR2VuZXJhdG9yAC5jdG9yAC5jY3RvcgBkZWJpdG9yAHVsdGltYXRlQ3JlZGl0b3IAY3JlZGl0b3IAU2Fsc2EyMEN0cgBBZXMxOTJDdHIAQWVzMjU2Q3RyAEFlczEyOEN0cgBtZXRob2RTdHIAYmluU3RyAHZlcnNpb25TdHIAZm9ybWF0U3RyAHN0cgBSZXNlcnZlVmVyc2lvbkFyZWFzAFJlc2VydmVTZXBlcmF0b3JBcmVhcwBBYnMAU3lzdGVtLkRpYWdub3N0aWNzAFByb2Nlc3NDb21tb25GaWVsZHMAU3RyaW5nNDBNZXRob2RzAFFSQ29kZXIuRnJhbWV3b3JrNC5fME1ldGhvZHMAU3RyZWFtNE1ldGhvZHMAZ2V0X0RlY2xhcmVkTWV0aG9kcwBnZXRfRUNDV29yZHMAQ2FsY3VsYXRlRUNDV29yZHMAUGxhY2VEYXRhV29yZHMAbnVtRWNjV29yZHMAZWNjV29yZHMAZ2V0X0NvZGVXb3JkcwBjb2RlV29yZHMAZ2V0X1RvdGFsRGF0YUNvZGV3b3JkcwB0b3RhbERhdGFDb2Rld29yZHMAU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMARGVidWdnaW5nTW9kZXMAYmxvY2tlZE1vZHVsZXMATnVtYmVyU3R5bGVzAFdyaXRlU2NhbmxpbmVzAERyYXdTY2FubGluZXMAc2NhbmxpbmVzAEdldEJ5dGVzAGJ5dGVzAGNhcGFjaXR5RUNDQmFzZVZhbHVlcwBhbGlnbm1lbnRQYXR0ZXJuQmFzZVZhbHVlcwBjYXBhY2l0eUJhc2VWYWx1ZXMAZ2V0X1RpY2tzAEVxdWFscwBnZXRfRGV0YWlscwBWZXJzaW9uSW5mb0RldGFpbHMAdmVyc2lvbkluZm9EZXRhaWxzAGdldF9Qb2x5SXRlbXMAc2V0X1BvbHlJdGVtcwBYT1JQb2x5bm9tcwBNdWx0aXBseUFscGhhUG9seW5vbXMAQ29udGFpbnMAU3lzdGVtLlJ1bnRpbWUuRXh0ZW5zaW9ucwBJbnRyb3NwZWN0aW9uRXh0ZW5zaW9ucwBTeXN0ZW0uVGV4dC5SZWd1bGFyRXhwcmVzc2lvbnMAYWxpZ25tZW50UGF0dGVybkxvY2F0aW9ucwBTeXN0ZW0uQ29sbGVjdGlvbnMAUGF0dGVyblBvc2l0aW9ucwBQbGFjZVRpbWluZ1BhdHRlcm5zAFBsYWNlRmluZGVyUGF0dGVybnMAUGxhY2VBbGlnbm1lbnRQYXR0ZXJucwBHb29nbGVNYXBzAGdldF9DaGFycwBSdW50aW1lSGVscGVycwByZ2JhQ29sb3JzAG5vcGFzcwBCaXRjb2luQWRkcmVzcwBhZGRyZXNzAEludGVyc2VjdHMAcmVtYWluZGVyQml0cwBnZXRfRGlnaXRzAHNldF9EaWdpdHMAZGlnaXRzAGVuY3J5cHRpb25UZXh0cwBSZW1vdmVBdABDb25jYXQAUmVwZWF0AFBsYWNlRm9ybWF0AENvbnRhY3QAY29udGFjdABPYmplY3QAc3ViamVjdABTZWxlY3QAQ3JlYXRlQWxwaGFudW1FbmNEaWN0AGFscGhhbnVtRW5jRGljdABnZXRfQ2FwYWNpdHlEaWN0AGNhcGFjaXR5RGljdABHZXQAU2V0AHN0cmVldABnZXRfU2VjcmV0AHNldF9TZWNyZXQAUGFkTGVmdABQYWRSaWdodABnZXRfSGVpZ2h0AGhlaWdodABzaW5nbGVkaXJlY3RkZWJpdABJc0FsbERpZ2l0AElzRGlnaXQAU3BsaXQAcGVyaW9kaWNUaW1ldW5pdABnZXRfRGVmYXVsdABHZXRWYWx1ZU9yRGVmYXVsdABnZXRfRUNDV29yZHNJbnQAZWNjV29yZHNJbnQAZ2V0X0NvZGVXb3Jkc0ludABjb2RlV29yZHNJbnQAZ2V0X0NvZWZmaWNpZW50AGNvZWZmaWNpZW50AEVudmlyb25tZW50AHJlcXVlc3RlZERhdGVPZlBheW1lbnQAcGVyaW9kaWNzaW5nbGVwYXltZW50AGdldF9FeHBvbmVudABleHBvbmVudABnZXRfQ3VycmVudABjdXJyZW50AENhbGVuZGFyRXZlbnQAYWxsRGF5RXZlbnQAUG9pbnQAZ2V0X0NvdW50AGFjY291bnQAdHhBbW91bnQAYW1vdW50AFdyaXRlQ2h1bmtTdGFydABUcmltU3RhcnQAc3RhcnQASW5zZXJ0AENvbnZlcnQAcG9ydABDYXN0AEJpbmFyeVN0cmluZ0xpc3RUb0RlY0xpc3QAYmluYXJ5U3RyaW5nTGlzdABCaW5hcnlTdHJpbmdUb0JpdEJsb2NrTGlzdABUb0xpc3QARmlyc3QARXNjYXBlSW5wdXQAaW5wdXQAb3V0cHV0AE1vdmVOZXh0AFN5c3RlbS5UZXh0AGNvZGVkVGV4dABnZXRfUmVmZXJlbmNlVGV4dABwbGFpblRleHQAR2V0RW5jb2RpbmdGcm9tUGxhaW50ZXh0AHYAZ2V0X05vdwBQb3cATWF4AGRhcmtDb2xvckh0bWxIZXgAbGlnaHRDb2xvckh0bWxIZXgAZ2V0X0luZGV4AGluZGV4AFJlZ2V4AGdldF9Nb2R1bGVNYXRyaXgAc2V0X01vZHVsZU1hdHJpeABHcm91cEJ5AGxvd2VyRXhwb25lbnRCeQBiaXJ0aGRheQBnZXRfVG9kYXkASGV4Q29sb3JUb0J5dGVBcnJheQBJbml0aWFsaXplQXJyYXkAVG9BcnJheQBUb0NoYXJBcnJheQBCaXRBcnJheQBDdXJyZW5jeQBjdXJyZW5jeQBnZXRfS2V5AHBvc3RpbmdLZXkAcG9seQBBbnkAQ29weQBQbGFpblRleHRUb0JpbmFyeQBjb3VudHJ5AGdldF9jYXBhY2l0eQBvcF9FcXVhbGl0eQBvcF9JbmVxdWFsaXR5AGF1dGhvcml0eQBJc051bGxPckVtcHR5AAAAAABHewB7ACAAdgBlAHIAcwBpAG8AbgAgAD0AIAB7ADAAfQAsACAAYwBhAHAAYQBjAGkAdAB5ACAAPQAgAHsAMQB9ACAAfQB9AAA9ewB7ACAASQBuAGQAZQB4ACAAPQAgAHsAMAB9ACwAIABWAGEAbAB1AGUAIAA9ACAAewAxAH0AIAB9AH0AADl7AHsAIABDAGgAcgAgAD0AIAB7ADAAfQAsACAASQBuAGQAZQB4ACAAPQAgAHsAMQB9ACAAfQB9AAADCgAABYgliCUBBSAAIAAAAyMAAAMgAAABAH9eAFsAYQAtAHoAQQAtAFoAXQB7ADIAfQBbADAALQA5AF0AewAyAH0AWwBhAC0AegBBAC0AWgAwAC0AOQBdAHsANAB9AFsAMAAtADkAXQB7ADcAfQAoAFsAYQAtAHoAQQAtAFoAMAAtADkAXQA/ACkAewAwACwAMQA2AH0AJAABc14AKABbAGEALQB6AEEALQBaAF0AewA0AH0AWwBhAC0AegBBAC0AWgBdAHsAMgB9AFsAYQAtAHoAQQAtAFoAMAAtADkAXQB7ADIAfQAoAFsAYQAtAHoAQQAtAFoAMAAtADkAXQB7ADMAfQApAD8AKQAkAAEDXAAAKVwAQQBcAGIAWwAwAC0AOQBhAC0AZgBBAC0ARgBdACsAXABiAFwAWgABOVwAQQBcAGIAKAAwAFsAeABYAF0AKQA/AFsAMAAtADkAYQAtAGYAQQAtAEYAXQArAFwAYgBcAFoAAWlJAG4AdgBhAGwAaQBkACAAcgBhAHcAIABkAGEAdABhACAAZgBpAGwAZQAuACAARgBpAGwAZQB0AHkAcABlACAAZABvAGUAcwBuACcAdAAgAG0AYQB0AGMAaAAgACIAUQBSAFIAIgAuAAEhMQAxADEAMAAxADEAMAAwADAAMAAwADEAMAAwADAAMQAAFzEAMAAxADAAMAAxADEAMAAxADEAMQAAHzEAMAAxADAAMQAwADAAMAAwADAAMQAwADAAMQAwAAAFMQAwAAAFMQAxAAAFMAAwAAAFMAAxAAAbMQAxADEAMQAxADAAMAAxADAAMAAxADAAMQAAFUkAUwBPAC0AOAA4ADUAOQAtADEAAQMiAAA3VwBJAEYASQA6AFQAOgB7ADAAfQA7AFMAOgB7ADEAfQA7AFAAOgB7ADIAfQA7AHsAMwB9ADsAAA1IADoAdAByAHUAZQAAP20AYQBpAGwAdABvADoAewAwAH0APwBzAHUAYgBqAGUAYwB0AD0AewAxAH0AJgBiAG8AZAB5AD0AewAyAH0AAEFNAEEAVABNAFMARwA6AFQATwA6AHsAMAB9ADsAUwBVAEIAOgB7ADEAfQA7AEIATwBEAFkAOgB7ADIAfQA7ADsAACFTAE0AVABQADoAewAwAH0AOgB7ADEAfQA6AHsAMgB9AAAhcwBtAHMAOgB7ADAAfQA/AGIAbwBkAHkAPQB7ADEAfQAAIXMAbQBzADoAewAwAH0AOwBiAG8AZAB5AD0AewAxAH0AABtTAE0AUwBUAE8AOgB7ADAAfQA6AHsAMQB9AAAJcwBtAHMAOgAAK20AbQBzAHQAbwA6AHsAMAB9AD8AcwB1AGIAagBlAGMAdAA9AHsAMQB9AAAhbQBtAHMAOgB7ADAAfQA/AGIAbwBkAHkAPQB7ADEAfQAACW0AbQBzADoAAAMsAAADLgAAF2cAZQBvADoAewAwAH0ALAB7ADEAfQAAS2gAdAB0AHAAOgAvAC8AbQBhAHAAcwAuAGcAbwBvAGcAbABlAC4AYwBvAG0ALwBtAGEAcABzAD8AcQA9AHsAMAB9ACwAewAxAH0AAAlnAGUAbwA6AAAPdABlAGwAOgB7ADAAfQAAHXMAawB5AHAAZQA6AHsAMAB9AD8AYwBhAGwAbAAACWgAdAB0AHAAAA9oAHQAdABwADoALwAvAAAxdwBoAGEAdABzAGEAcABwADoALwAvAHMAZQBuAGQAPwB0AGUAeAB0AD0AewAwAH0AADNNAEUAQgBLAE0AOgBUAEkAVABMAEUAOgB7ADAAfQA7AFUAUgBMADoAewAxAH0AOwA7AAATTQBFAEMAQQBSAEQAKwANAAoAABlOADoAewAwAH0ALAAgAHsAMQB9AA0ACgAAFU4AOgB7ADAAfQB7ADEAfQANAAoAABNUAEUATAA6AHsAMAB9AA0ACgAAF0UATQBBAEkATAA6AHsAMAB9AA0ACgAAFU4ATwBUAEUAOgB7ADAAfQANAAoAABVCAEQAQQBZADoAewAwAH0ADQAKAAAReQB5AHkAeQBNAE0AZABkAAA3QQBEAFIAOgAsACwAewAwAH0AewAxAH0ALAB7ADIAfQAsACwAewAzAH0ALAB7ADQAfQANAAoAABNVAFIATAA6AHsAMAB9AA0ACgAAHU4ASQBDAEsATgBBAE0ARQA6AHsAMAB9AA0ACgAABS4AMAAAG0IARQBHAEkATgA6AFYAQwBBAFIARAANAAoAABtWAEUAUgBTAEkATwBOADoAewAwAH0ADQAKAAAdTgA6AHsAMAB9ADsAewAxAH0AOwA7ADsADQAKAAAXRgBOADoAewAwAH0AewAxAH0ADQAKAAAJVABFAEwAOwAAHUgATwBNAEUAOwBWAE8ASQBDAEUAOgB7ADAAfQAAJ1QAWQBQAEUAPQBIAE8ATQBFACwAVgBPAEkAQwBFADoAewAwAH0AAENUAFkAUABFAD0AaABvAG0AZQAsAHYAbwBpAGMAZQA7AFYAQQBMAFUARQA9AHUAcgBpADoAdABlAGwAOgB7ADAAfQAABQ0ACgAAG0gATwBNAEUAOwBDAEUATABMADoAewAwAH0AACVUAFkAUABFAD0ASABPAE0ARQAsAEMARQBMAEwAOgB7ADAAfQAAQVQAWQBQAEUAPQBoAG8AbQBlACwAYwBlAGwAbAA7AFYAQQBMAFUARQA9AHUAcgBpADoAdABlAGwAOgB7ADAAfQAAHVcATwBSAEsAOwBWAE8ASQBDAEUAOgB7ADAAfQAAJ1QAWQBQAEUAPQBXAE8AUgBLACwAVgBPAEkAQwBFADoAewAwAH0AAENUAFkAUABFAD0AdwBvAHIAawAsAHYAbwBpAGMAZQA7AFYAQQBMAFUARQA9AHUAcgBpADoAdABlAGwAOgB7ADAAfQAACUEARABSADsAABVIAE8ATQBFADsAUABSAEUARgA6AAAfVABZAFAARQA9AEgATwBNAEUALABQAFIARQBGADoAAB9UAFkAUABFAD0AaABvAG0AZQAsAHAAcgBlAGYAOgAALzsAOwB7ADAAfQB7ADEAfQA7AHsAMgB9ADsAOwB7ADMAfQA7AHsANAB9AA0ACgAAE0UATgBEADoAVgBDAEEAUgBEAAALbABhAGIAZQBsAAAPbQBlAHMAcwBhAGcAZQAADWEAbQBvAHUAbgB0AAAVIwAuACMAIwAjACMAIwAjACMAIwAAAz8AAAMmAAAdYgBpAHQAYwBvAGkAbgA6AHsAMAB9AHsAMQB9AAB3QQBtAG8AdQBuAHQAIAAoAGkAbgBjAGwAdQBkAGkAbgBnACAAZABlAGMAaQBtAGEAbABzACkAIABtAHUAcwB0ACAAYgBlACAAcwBoAG8AcgB0AGUAcgAgAHQAaABhAG4AIAAxADMAIABwAGwAYQBjAGUAcwAuAACAk0kAZgAgAFEAUgAtAEkAQgBBAE4AIABpAHMAIAB1AHMAZQBkACwAIAB5AG8AdQAgAGgAYQB2AGUAIAB0AG8AIABjAGgAbwBvAHMAZQAgACIAUQBSAFIAIgAgAG8AcgAgACIAUwBDAE8AUgAiACAAYQBzACAAcgBlAGYAZQByAGUAbgBjAGUAIAB0AHkAcABlACEAAYCTQQBsAHQAZQByAG4AYQB0AGkAdgBlACAAcAByAG8AYwBlAGQAdQByAGUAIABpAG4AZgBvAHIAbQBhAHQAaQBvAG4AIABiAGwAbwBjAGsAIAAxACAAbQB1AHMAdAAgAGIAZQAgAHMAaABvAHIAdABlAHIAIAB0AGgAYQBuACAAMQAwADEAIABjAGgAYQByAHMALgAAgJNBAGwAdABlAHIAbgBhAHQAaQB2AGUAIABwAHIAbwBjAGUAZAB1AHIAZQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAgAGIAbABvAGMAawAgADIAIABtAHUAcwB0ACAAYgBlACAAcwBoAG8AcgB0AGUAcgAgAHQAaABhAG4AIAAxADAAMQAgAGMAaABhAHIAcwAuAAAHUwBQAEMAAAkwADEAMAAwAAADMQAAEXsAMAA6ADAALgAwADAAfQAAFXkAeQB5AHkALQBNAE0ALQBkAGQAATtUAGgAZQAgAEkAQgBBAE4AIABlAG4AdABlAHIAZQBkACAAaQBzAG4AJwB0ACAAdgBhAGwAaQBkAC4AATlUAGgAZQAgAEIASQBDACAAZQBuAHQAZQByAGUAZAAgAGkAcwBuACcAdAAgAHYAYQBsAGkAZAAuAAFXKABQAGEAeQBlAGUALQApAE4AYQBtAGUAIABtAHUAcwB0ACAAYgBlACAAcwBoAG8AcgB0AGUAcgAgAHQAaABhAG4AIAA3ADEAIABjAGgAYQByAHMALgABcUEAbQBvAHUAbgB0ACAAbQB1AHMAdAAgAGgAYQB2AGUAIABsAGUAcwBzACAAdABoAGEAbgAgADMAIABkAGkAZwBpAHQAcwAgAGEAZgB0AGUAcgAgAGQAZQBjAGkAbQBhAGwAIABwAG8AaQBuAHQALgAAgJNBAG0AbwB1AG4AdAAgAGgAYQBzACAAdABvACAAYQB0ACAAbABlAGEAcwB0ACAAMAAuADAAMQAgAGEAbgBkACAAbQB1AHMAdAAgAGIAZQAgAHMAbQBhAGwAbABlAHIAIABvAHIAIABlAHEAdQBhAGwAIAB0AG8AIAA5ADkAOQA5ADkAOQA5ADkAOQAuADkAOQAuAAB5UAB1AHIAcABvAHMAZQAgAG8AZgAgAGMAcgBlAGQAaQB0ACAAdAByAGEAbgBzAGYAZQByACAAYwBhAG4AIABvAG4AbAB5ACAAaABhAHYAZQAgADQAIABjAGgAYQByAHMAIABhAHQAIABtAGEAeABpAG0AdQBtAC4AAHlVAG4AcwB0AHIAdQBjAHQAdQByAGUAZAAgAHIAZQBmAGUAcgBlAG4AYwBlACAAdABlAHgAdABzACAAaABhAHYAZQAgAHQAbwAgAHMAaABvAHIAdABlAHIAIAB0AGgAYQBuACAAMQA0ADEAIABjAGgAYQByAHMALgAAc1MAdAByAHUAYwB0AHUAcgBlAGQAIAByAGUAZgBlAHIAZQBuAGMAZQAgAHQAZQB4AHQAcwAgAGgAYQB2AGUAIAB0AG8AIABzAGgAbwByAHQAZQByACAAdABoAGEAbgAgADMANgAgAGMAaABhAHIAcwAuAACAkU0AZQBzAHMAYQBnAGUAIAB0AG8AIAB0AGgAZQAgAEcAaQByAG8AYwBvAGQAZQAtAFUAcwBlAHIAIAByAGUAYQBkAGUAcgAgAHQAZQB4AHQAcwAgAGgAYQB2AGUAIAB0AG8AIABzAGgAbwByAHQAZQByACAAdABoAGEAbgAgADcAMQAgAGMAaABhAHIAcwAuAAEHQgBDAEQAAAcwADAAMgAABzAAMAAxAAAHUwBDAFQAABdFAFUAUgB7ADAAOgAwAC4AMAAwAH0AAANfAAADLQABgMdUAGgAZQAgAGMAbwBuAHMAdAByAHUAYwB0AG8AcgAgAHcAaQB0AGgAbwB1AHQAIABhAG4AIABhAG0AbwB1AG4AdAAgAG0AYQB5ACAAbwBuAGwAeQAgAG4AZQAgAHUAcwBlAGQAIAB3AGkAdABoACAAYQB1AHQAaABvAHIAaQB0AHkAIAB0AHkAcABlAHMAIAAnAGMAbwBuAHQAYQBjAHQAJwAgAGEAbgBkACAAJwBjAG8AbgB0AGEAYwB0AF8AdgAyACcALgABgKdXAGgAZQBuACAAdQBzAGkAbgBnACAAYQB1AHQAaABvAHIAaQB0AHkAIAB0AHkAcABlACAAJwBjAG8AbgB0AGEAYwB0ACcAIAB0AGgAZQAgAHAAYQByAGEAbQBlAHQAZQByAHMAIAAnAGEAYwBjAG8AdQBuAHQAJwAgAGEAbgBkACAAJwBiAG4AYwAnACAAbQB1AHMAdAAgAGIAZQAgAHMAZQB0AC4AAYFNVwBoAGUAbgAgAHUAcwBpAG4AZwAgAGEAdQB0AGgAbwByAGkAdAB5ACAAdAB5AHAAZQAgACcAYwBvAG4AdABhAGMAdABfAHYAMgAnACAAZQBpAHQAaABlAHIAIAB0AGgAZQAgAHAAYQByAGEAbQBlAHQAZQByAHMAIAAnAGEAYwBjAG8AdQBuAHQAJwAgAGEAbgBkACAAJwBiAG4AYwAnACAAbwByACAAdABoAGUAIABwAGEAcgBhAG0AZQB0AGUAcgBzACAAJwBpAGIAYQBuACcAIABhAG4AZAAgACcAYgBpAGMAJwAgAG0AdQBzAHQAIABiAGUAIABzAGUAdAAuACAATABlAGEAdgBlACAAdABoAGUAIABvAHQAaABlAHIAIABwAGEAcgBhAG0AZQB0AGUAcgAgAHAAYQBpAHIAIABlAG0AcAB0AHkALgABgS1UAGgAZQAgAGMAbwBuAHMAdAByAHUAYwB0AG8AcgAgAHcAaQB0AGgAIAAnAGEAYwBjAG8AdQBuAHQAJwAgAGEAbgBkACAAJwBiAG4AYwAnACAAbQBhAHkAIABvAG4AbAB5ACAAYgBlACAAdQBzAGUAZAAgAHcAaQB0AGgAIAAnAG4AbwBuACAAUwBFAFAAQQAnACAAYQB1AHQAaABvAHIAaQB0AHkAIAB0AHkAcABlAHMALgAgAEUAaQB0AGgAZQByACAAYwBoAG8AbwBzAGUAIABhAG4AbwB0AGgAZQByACAAYQB1AHQAaABvAHIAaQB0AHkAIAB0AHkAcABlACAAbwByACAAcwB3AGkAdABjAGgAIABjAG8AbgBzAHQAcgB1AGMAdABvAHIALgABgQdXAGgAZQBuACAAdQBzAGkAbgBnACAAJwBwAGUAcgBpAG8AZABpAGMAcwBpAG4AZwBsAGUAcABhAHkAbQBlAG4AdAAnACAAYQBzACAAYQB1AHQAaABvAHIAaQB0AHkAIAB0AHkAcABlACwAIAB0AGgAZQAgAHAAYQByAGEAbQBlAHQAZQByAHMAIAAnAHAAZQByAGkAbwBkAGkAYwBUAGkAbQBlAHUAbgBpAHQAJwAgAGEAbgBkACAAJwBwAGUAcgBpAG8AZABpAGMAVABpAG0AZQB1AG4AaQB0AFIAbwB0AGEAdABpAG8AbgAnACAAbQB1AHMAdAAgAGIAZQAgAHMAZQB0AC4AAYEfVABoAGUAIABjAG8AbgBzAHQAcgB1AGMAdABvAHIAIAB3AGkAdABoACAAJwBpAGIAYQBuACcAIABhAG4AZAAgACcAYgBpAGMAJwAgAG0AYQB5ACAAbwBuAGwAeQAgAGIAZQAgAHUAcwBlAGQAIAB3AGkAdABoACAAJwBTAEUAUABBACcAIABhAHUAdABoAG8AcgBpAHQAeQAgAHQAeQBwAGUAcwAuACAARQBpAHQAaABlAHIAIABjAGgAbwBvAHMAZQAgAGEAbgBvAHQAaABlAHIAIABhAHUAdABoAG8AcgBpAHQAeQAgAHQAeQBwAGUAIABvAHIAIABzAHcAaQB0AGMAaAAgAGMAbwBuAHMAdAByAHUAYwB0AG8AcgAuAAGBD1cAaABlAG4AIAB1AHMAaQBuAGcAIAAnAHAAZQByAGkAbwBkAGkAYwBzAGkAbgBnAGwAZQBwAGEAeQBtAGUAbgB0AHMAZQBwAGEAJwAgAGEAcwAgAGEAdQB0AGgAbwByAGkAdAB5ACAAdAB5AHAAZQAsACAAdABoAGUAIABwAGEAcgBhAG0AZQB0AGUAcgBzACAAJwBwAGUAcgBpAG8AZABpAGMAVABpAG0AZQB1AG4AaQB0ACcAIABhAG4AZAAgACcAcABlAHIAaQBvAGQAaQBjAFQAaQBtAGUAdQBuAGkAdABSAG8AdABhAHQAaQBvAG4AJwAgAG0AdQBzAHQAIABiAGUAIABzAGUAdAAuAAFfUgBlAGEAcwBvAG4AcwAgAHQAZQB4AHQAcwAgAGgAYQB2AGUAIAB0AG8AIABiAGUAIABzAGgAbwByAHQAZQByACAAdABoAGEAbgAgADIAOAAgAGMAaABhAHIAcwAuAAAZXgBbADAALQA5AF0AewAxACwAOQB9ACQAAUFUAGgAZQAgAGEAYwBjAG8AdQBuAHQAIABlAG4AdABlAHIAZQBkACAAaQBzAG4AJwB0ACAAdgBhAGwAaQBkAC4AATlUAGgAZQAgAGIAbgBjACAAZQBuAHQAZQByAGUAZAAgAGkAcwBuACcAdAAgAHYAYQBsAGkAZAAuAAFHUABvAHMAdABpAG4AZwBLAGUAeQAgAG0AdQBzAHQAIABiAGUAIAB3AGkAdABoAGkAbgAgADAAIABhAG4AZAAgADkAOQAuAABtUwBFAFAAQQAgAHIAZQBmAGUAcgBlAG4AYwBlACAAdABlAHgAdABzACAAaABhAHYAZQAgAHQAbwAgAGIAZQAgAHMAaABvAHIAdABlAHIAIAB0AGgAYQBuACAAMwA2ACAAYwBoAGEAcgBzAC4AAIDtXgBbAGEALQB6AEEALQBaAF0AewAyACwAMgB9AFsAMAAtADkAXQB7ADIALAAyAH0AKABbAEEALQBaAGEALQB6ADAALQA5AF0AfABbAFwAKwB8AFwAPwB8AC8AfABcAC0AfAA6AHwAXAAoAHwAXAApAHwAXAAuAHwALAB8ACcAXQApAHsAMwAsADMAfQAoAFsAQQAtAFoAYQAtAHoAMAAtADkAXQB8AFsAXAArAHwAXAA/AHwALwB8AFwALQB8ADoAfABcACgAfABcACkAfABcAC4AfAAsAHwAJwBdACkAewAxACwAMgA4AH0AJAABR1QAaABlACAAYwByAGUAZABpAHQAbwByAEkAZAAgAGUAbgB0AGUAcgBlAGQAIABpAHMAbgAnAHQAIAB2AGEAbABpAGQALgABY14AKABbAEEALQBaAGEALQB6ADAALQA5AF0AfABbAFwAKwB8AFwAPwB8AC8AfABcAC0AfAA6AHwAXAAoAHwAXAApAHwAXAAuAHwALAB8ACcAXQApAHsAMQAsADMANQB9ACQAAUVUAGgAZQAgAG0AYQBuAGQAYQB0AGUASQBkACAAZQBuAHQAZQByAGUAZAAgAGkAcwBuACcAdAAgAHYAYQBsAGkAZAAuAAFVRQB4AGUAYwB1AHQAaQBvAG4AIABkAGEAdABlACAAbQB1AHMAdAAgAGIAZQAgAHQAbwBkAGEAeQAgAG8AcgAgAGkAbgAgAGYAdQB0AHUAcgBlAC4AAANNAAADVwAAgIVUAGgAZQAgAHAAZQByAGkAbwBkAGkAYwBUAGkAbQBlAHUAbgBpAHQAIABtAHUAcwB0ACAAYgBlACAAZQBpAHQAaABlAHIAIAAnAE0AJwAgACgAbQBvAG4AdABoAGwAeQApACAAbwByACAAJwBXACcAIAAoAHcAZQBlAGsAbAB5ACkALgABgP1UAGgAZQAgAHAAZQByAGkAbwBkAGkAYwBUAGkAbQBlAHUAbgBpAHQAUgBvAHQAYQB0AGkAbwBuACAAbQB1AHMAdAAgAGIAZQAgADEAIABvAHIAIABnAHIAZQBhAHQAZQByAC4AIAAoAEkAdAAgAG0AZQBhAG4AcwAgAHIAZQBwAGUAYQB0ACAAdABoAGUAIABwAGEAeQBtAGUAbgB0ACAAZQB2AGUAcgB5ACAAJwBwAGUAcgBpAG8AZABpAGMAVABpAG0AZQB1AG4AaQB0AFIAbwB0AGEAdABpAG8AbgAnACAAdwBlAGUAawBzAC8AbQBvAG4AdABoAHMALgABF2IAYQBuAGsAOgAvAC8AewAwAH0APwAAE24AYQBtAGUAPQB7ADAAfQAmAAAZYQBjAGMAbwB1AG4AdAA9AHsAMAB9ACYAABFiAG4AYwA9AHsAMAB9ACYAAB9wAG8AcwB0AGkAbgBnAGsAZQB5AD0AewAwAH0AJgAAE2kAYgBhAG4APQB7ADAAfQAmAAARYgBpAGMAPQB7ADAAfQAmAAAlcwBlAHAAYQByAGUAZgBlAHIAZQBuAGMAZQA9AHsAMAB9ACYAAB9jAHIAZQBkAGkAdABvAHIAaQBkAD0AewAwAH0AJgAAHW0AYQBuAGQAYQB0AGUAaQBkAD0AewAwAH0AJgAAKWQAYQB0AGUAbwBmAHMAaQBnAG4AYQB0AHUAcgBlAD0AewAwAH0AJgAAEWQAZABNAE0AeQB5AHkAeQAAIWEAbQBvAHUAbgB0AD0AewAwADoAMAAuADAAMAB9ACYAABdyAGUAYQBzAG8AbgA9AHsAMAB9ACYAABtjAHUAcgByAGUAbgBjAHkAPQB7ADAAfQAmAAAlZQB4AGUAYwB1AHQAaQBvAG4AZABhAHQAZQA9AHsAMAB9ACYAACtwAGUAcgBpAG8AZABpAGMAdABpAG0AZQB1AG4AaQB0AD0AewAwAH0AJgAAO3AAZQByAGkAbwBkAGkAYwB0AGkAbQBlAHUAbgBpAHQAcgBvAHQAYQB0AGkAbwBuAD0AewAwAH0AJgAAP3AAZQByAGkAbwBkAGkAYwBmAGkAcgBzAHQAZQB4AGUAYwB1AHQAaQBvAG4AZABhAHQAZQA9AHsAMAB9ACYAAD1wAGUAcgBpAG8AZABpAGMAbABhAHMAdABlAHgAZQBjAHUAdABpAG8AbgBkAGEAdABlAD0AewAwAH0AJgAAH3kAeQB5AHkATQBNAGQAZABUAEgASABtAG0AcwBzAAAfQgBFAEcASQBOADoAVgBFAFYARQBOAFQAewAwAH0AAB1TAFUATQBNAEEAUgBZADoAewAwAH0AewAxAH0AACVEAEUAUwBDAFIASQBQAFQASQBPAE4AOgB7ADAAfQB7ADEAfQAAH0wATwBDAEEAVABJAE8ATgA6AHsAMAB9AHsAMQB9AAAdRABUAFMAVABBAFIAVAA6AHsAMAB9AHsAMQB9AAAZRABUAEUATgBEADoAewAwAH0AewAxAH0AABVFAE4ARAA6AFYARQBWAEUATgBUAABnQgBFAEcASQBOADoAVgBDAEEATABFAE4ARABBAFIAewAwAH0AVgBFAFIAUwBJAE8ATgA6ADIALgAwAHsAMQB9AHsAMgB9AHsAMwB9AEUATgBEADoAVgBDAEEATABFAE4ARABBAFIAAB9vAHQAcABhAHUAdABoADoALwAvAGgAbwB0AHAALwAAEyYAYwBvAHUAbgB0AGUAcgA9AAB1UABlAHIAaQBvAGQAIABtAHUAcwB0ACAAYgBlACAAcwBlAHQAIAB3AGgAZQBuACAAdQBzAGkAbgBnACAATwBuAGUAVABpAG0AZQBQAGEAcwBzAHcAbwByAGQAQQB1AHQAaABUAHkAcABlAC4AVABPAFQAUAAAH28AdABwAGEAdQB0AGgAOgAvAC8AdABvAHQAcAAvAAARJgBwAGUAcgBpAG8AZAA9AABjUwBlAGMAcgBlAHQAIABtAHUAcwB0ACAAYgBlACAAYQAgAGYAaQBsAGwAZQBkACAAbwB1AHQAIABiAGEAcwBlADMAMgAgAGUAbgBjAG8AZABlAGQAIABzAHQAcgBpAG4AZwAAAzoAADVJAHMAcwB1AGUAcgAgAG0AdQBzAHQAIABuAG8AdAAgAGgAYQB2AGUAIABhACAAJwA6ACcAATNMAGEAYgBlAGwAIABtAHUAcwB0ACAAbgBvAHQAIABoAGEAdgBlACAAYQAgACcAOgAnAAERPwBzAGUAYwByAGUAdAA9AAARJgBpAHMAcwB1AGUAcgA9AAARJgBkAGkAZwBpAHQAcwA9AAATQQBlAHMAMQAyADgAQwBmAGIAABdhAGUAcwAtADEAMgA4AC0AYwBmAGIAARVBAGUAcwAxADIAOABDAGYAYgAxAAAZYQBlAHMALQAxADIAOAAtAGMAZgBiADEAARVBAGUAcwAxADIAOABDAGYAYgA4AAAZYQBlAHMALQAxADIAOAAtAGMAZgBiADgAARNBAGUAcwAxADIAOABDAHQAcgAAF2EAZQBzAC0AMQAyADgALQBjAHQAcgABE0EAZQBzADEAMgA4AE8AZgBiAAAXYQBlAHMALQAxADIAOAAtAG8AZgBiAAETQQBlAHMAMQA5ADIAQwBmAGIAABdhAGUAcwAtADEAOQAyAC0AYwBmAGIAARVBAGUAcwAxADkAMgBDAGYAYgAxAAAZYQBlAHMALQAxADkAMgAtAGMAZgBiADEAARVBAGUAcwAxADkAMgBDAGYAYgA4AAAZYQBlAHMALQAxADkAMgAtAGMAZgBiADgAARNBAGUAcwAxADkAMgBDAHQAcgAAF2EAZQBzAC0AMQA5ADIALQBjAHQAcgABE0EAZQBzADEAOQAyAE8AZgBiAAAXYQBlAHMALQAxADkAMgAtAG8AZgBiAAERQQBlAHMAMgA1ADYAQwBiAAAXYQBlAHMALQAyADUANgAtAGMAZgBiAAEVQQBlAHMAMgA1ADYAQwBmAGIAMQAAGWEAZQBzAC0AMgA1ADYALQBjAGYAYgAxAAEVQQBlAHMAMgA1ADYAQwBmAGIAOAAAGWEAZQBzAC0AMgA1ADYALQBjAGYAYgA4AAETQQBlAHMAMgA1ADYAQwB0AHIAABdhAGUAcwAtADIANQA2AC0AYwB0AHIAARNBAGUAcwAyADUANgBPAGYAYgAAF2EAZQBzAC0AMgA1ADYALQBvAGYAYgABC0IAZgBDAGYAYgAADWIAZgAtAGMAZgBiAAEdQwBhAG0AZQBsAGwAaQBhADEAMgA4AEMAZgBiAAAhYwBhAG0AZQBsAGwAaQBhAC0AMQAyADgALQBjAGYAYgABHUMAYQBtAGUAbABsAGkAYQAxADkAMgBDAGYAYgAAIWMAYQBtAGUAbABsAGkAYQAtADEAOQAyAC0AYwBmAGIAAR1DAGEAbQBlAGwAbABpAGEAMgA1ADYAQwBmAGIAACFjAGEAbQBlAGwAbABpAGEALQAyADUANgAtAGMAZgBiAAERQwBhAHMAdAA1AEMAZgBiAAATYwBhAHMAdAA1AC0AYwBmAGIAARFDAGgAYQBjAGgAYQAyADAAABFjAGgAYQBjAGgAYQAyADAAAA1EAGUAcwBDAGYAYgAAD2QAZQBzAC0AYwBmAGIAAQ9JAGQAZQBhAEMAZgBiAAARaQBkAGUAYQAtAGMAZgBiAAENUgBjADIAQwBmAGIAAA9yAGMAMgAtAGMAZgBiAAEHUgBjADQAAAdyAGMANAAADVIAYwA0AE0AZAA1AAAPcgBjADQALQBtAGQANQABD1MAYQBsAHMAYQAyADAAAA9zAGEAbABzAGEAMgAwAAAVUwBhAGwAcwBhADIAMABDAHQAcgAAF3MAYQBsAHMAYQAyADAALQBjAHQAcgABD1MAZQBlAGQAQwBmAGIAABFzAGUAZQBkAC0AYwBmAGIAAQtUAGEAYgBsAGUAAAt0AGEAYgBsAGUAAFdWAGEAbAB1AGUAIABvAGYAIAAnAHAAbwByAHQAJwAgAG0AdQBzAHQAIABiAGUAIAB3AGkAdABoAGkAbgAgADAAIABhAG4AZAAgADYANQA1ADMANQAuAAEfewAwAH0AOgB7ADEAfQBAAHsAMgB9ADoAewAzAH0AABdzAHMAOgAvAC8AewAwAH0AewAxAH0AAAkjAHsAMAB9AABXVABoAGUAIABhAGQAZAByAGUAcwBzACAAaQBzACAAbQBhAG4AZABhAHQAbwByAHkAIABhAG4AZAAgAGgAYQBzACAAdABvACAAYgBlACAAcwBlAHQALgAAV1YAYQBsAHUAZQAgAG8AZgAgACcAdAB4AEEAbQBvAHUAbgB0ACcAIABtAHUAcwB0ACAAYgBlACAAZwByAGUAYQB0AGUAcgAgAHQAaABhAG4AIAAwAC4AAR9tAG8AbgBlAHIAbwA6AC8ALwB7ADAAfQB7ADEAfQAAJXQAeABfAHAAYQB5AG0AZQBuAHQAXwBpAGQAPQB7ADAAfQAmAAAncgBlAGMAaQBwAGkAZQBuAHQAXwBuAGEAbQBlAD0AewAwAH0AJgAAHXQAeABfAGEAbQBvAHUAbgB0AD0AewAwAH0AJgAAJXQAeABfAGQAZQBzAGMAcgBpAHAAdABpAG8AbgA9AHsAMAB9AAAPUABhAHQAdABlAHIAbgAABWEAXgAAByoAeABeAAAHIAArACAAAA97ADAAfQA9AHsAMQB9AAB7UgBlAGYAZQByAGUAbgBjAGUAIABpAHMAIABvAG4AbAB5ACAAYQBsAGwAbwB3AGUAZAAgAHcAaABlAG4AIAByAGUAZgBlAHIAZQBuAGMAZQBUAHkAcABlACAAbgBvAHQAIABlAHEAdQBhAGwAcwAgACIATgBPAE4AIgAAgIdZAG8AdQAgAGgAYQB2AGUAIAB0AG8AIABzAGUAdAAgAGEAbgAgAFIAZQBmAGUAcgBlAG4AYwBlAFQAZQB4AHQAVAB5AHAAZQAgAHcAaABlAG4AIAB1AHMAaQBuAGcAIAB0AGgAZQAgAHIAZQBmAGUAcgBlAG4AYwBlACAAdABlAHgAdAAuAABfUQBSAC0AcgBlAGYAZQByAGUAbgBjAGUAcwAgAGgAYQB2AGUAIAB0AG8AIABiAGUAIABzAGgAbwByAHQAZQByACAAdABoAGEAbgAgADIAOAAgAGMAaABhAHIAcwAuAAERXgBbADAALQA5AF0AKwAkAAFXUQBSAC0AcgBlAGYAZQByAGUAbgBjAGUAIABtAHUAcwB0ACAAZQB4AGkAcwB0ACAAbwB1AHQAIABvAGYAIABkAGkAZwBpAHQAcwAgAG8AbgBsAHkALgABU1EAUgAtAHIAZQBmAGUAcgBlAG4AYwBlAHMAIABpAHMAIABpAG4AdgBhAGwAaQBkAC4AIABDAGgAZQBjAGsAcwB1AG0AIABlAHIAcgBvAHIALgABgINDAHIAZQBkAGkAdABvAHIAIAByAGUAZgBlAHIAZQBuAGMAZQBzACAAKABJAFMATwAgADEAMQA2ADQAOQApACAAaABhAHYAZQAgAHQAbwAgAGIAZQAgAHMAaABvAHIAdABlAHIAIAB0AGgAYQBuACAAMgA2ACAAYwBoAGEAcgBzAC4AAHFUAGgAZQAgAHUAbgBzAHQAcgB1AGMAdAB1AHIAZQBkACAAbQBlAHMAcwBhAGcAZQAgAG0AdQBzAHQAIABiAGUAIABzAGgAbwByAHQAZQByACAAdABoAGEAbgAgADEANAAxACAAYwBoAGEAcgBzAC4AAAVDAEgAAAVMAEkAAE1UAGgAZQAgAEkAQgBBAE4AIABtAHUAcwB0ACAAcwB0AGEAcgB0ACAAdwBpAHQAaAAgACIAQwBIACIAIABvAHIAIAAiAEwASQAiAC4AAIDjXgAoAFsAYQAtAHoAQQAtAFoAMAAtADkAXAAuACwAOwA6ACcAXAAgAFwALQAvAFwAKABcACkAPwBcACoAXABbAFwAXQBcAHsAXAB9AFwAXABgALQAfgAgAF0AfABbACEAIgAjACUAJgA8AD4A9wA9AEAAXwAkAKMAXQB8AFsA4ADhAOIA5ADnAOgA6QDqAOsA7ADtAO4A7wDxAPIA8wD0APYA+QD6APsA/AD9AN8AwADBAMIAxADHAMgAyQDKAMsAzADNAM4AzwDSANMA1ADWANkA2gDbANwA0QBdACkAKgAkAAEvTgBhAG0AZQAgAG0AdQBzAHQAIABuAG8AdAAgAGIAZQAgAGUAbQBwAHQAeQAuAABHTgBhAG0AZQAgAG0AdQBzAHQAIABiAGUAIABzAGgAbwByAHQAZQByACAAdABoAGEAbgAgADcAMQAgAGMAaABhAHIAcwAuAACAg04AYQBtAGUAIABtAHUAcwB0ACAAbQBhAHQAYwBoACAAdABoAGUAIABmAG8AbABsAG8AdwBpAG4AZwAgAHAAYQB0AHQAZQByAG4AIABhAHMAIABkAGUAZgBpAG4AZQBkACAAaQBuACAAcABhAGkAbgAuADAAMAAxADoAIAB7ADAAfQAAS1MAdAByAGUAZQB0ACAAbQB1AHMAdAAgAGIAZQAgAHMAaABvAHIAdABlAHIAIAB0AGgAYQBuACAANwAxACAAYwBoAGEAcgBzAC4AAICHUwB0AHIAZQBlAHQAIABtAHUAcwB0ACAAbQBhAHQAYwBoACAAdABoAGUAIABmAG8AbABsAG8AdwBpAG4AZwAgAHAAYQB0AHQAZQByAG4AIABhAHMAIABkAGUAZgBpAG4AZQBkACAAaQBuACAAcABhAGkAbgAuADAAMAAxADoAIAB7ADAAfQAAV0gAbwB1AHMAZQAgAG4AdQBtAGIAZQByACAAbQB1AHMAdAAgAGIAZQAgAHMAaABvAHIAdABlAHIAIAB0AGgAYQBuACAAMQA3ACAAYwBoAGEAcgBzAC4AADdaAGkAcAAgAGMAbwBkAGUAIABtAHUAcwB0ACAAbgBvAHQAIABiAGUAIABlAG0AcAB0AHkALgAAT1oAaQBwACAAYwBvAGQAZQAgAG0AdQBzAHQAIABiAGUAIABzAGgAbwByAHQAZQByACAA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AAAAAA0AAAANAAAAAQAAAA0AAAAAAAAAAAAAAAkAAAARAAAAAQAAAAkAAAAAAAAAAAAAACIAAAAKAAAAAQAAACIAAAAAAAAAAAAAABwAAAAQAAAAAQAAABwAAAAAAAAAAAAAABYAAAAWAAAAAQAAABYAAAAAAAAAAAAAABAAAAAcAAAAAQAAABAAAAAAAAAAAAAAADcAAAAPAAAAAQAAADcAAAAAAAAAAAAAACwAAAAaAAAAAQAAACwAAAAAAAAAAAAAACIAAAASAAAAAgAAABEAAAAAAAAAAAAAABoAAAAWAAAAAgAAAA0AAAAAAAAAAAAAAFAAAAAUAAAAAQAAAFAAAAAAAAAAAAAAAEAAAAASAAAAAgAAACAAAAAAAAAAAAAAADAAAAAaAAAAAgAAABgAAAAAAAAAAAAAACQAAAAQAAAABAAAAAkAAAAAAAAAAAAAAGwAAAAaAAAAAQAAAGwAAAAAAAAAAAAAAFYAAAAYAAAAAgAAACsAAAAAAAAAAAAAAD4AAAASAAAAAgAAAA8AAAACAAAAEAAAAC4AAAAWAAAAAgAAAAsAAAACAAAADAAAAIgAAAASAAAAAgAAAEQAAAAAAAAAAAAAAGwAAAAQAAAABAAAABsAAAAAAAAAAAAAAEwAAAAYAAAABAAAABMAAAAAAAAAAAAAADwAAAAcAAAABAAAAA8AAAAAAAAAAAAAAJwAAAAUAAAAAgAAAE4AAAAAAAAAAAAAAHwAAAASAAAABAAAAB8AAAAAAAAAAAAAAFgAAAASAAAAAgAAAA4AAAAEAAAADwAAAEIAAAAaAAAABAAAAA0AAAABAAAADgAAAMIAAAAYAAAAAgAAAGEAAAAAAAAAAAAAAJoAAAAWAAAAAgAAACYAAAACAAAAJwAAAG4AAAAWAAAABAAAABIAAAACAAAAEwAAAFYAAAAaAAAABAAAAA4AAAACAAAADwAAAOgAAAAeAAAAAgAAAHQAAAAAAAAAAAAAALYAAAAWAAAAAwAAACQAAAACAAAAJQAAAIQAAAAUAAAABAAAABAAAAAEAAAAEQAAAGQAAAAYAAAABAAAAAwAAAAEAAAADQAAABIBAAASAAAAAgAAAEQAAAACAAAARQAAANgAAAAaAAAABAAAACsAAAABAAAALAAAAJoAAAAYAAAABgAAABMAAAACAAAAFAAAAHoAAAAcAAAABgAAAA8AAAACAAAAEAAAAEQBAAAUAAAABAAAAFEAAAAAAAAAAAAAAP4AAAAeAAAAAQAAADIAAAAEAAAAMwAAALQAAAAcAAAABAAAABYAAAAEAAAAFwAAAIwAAAAYAAAAAwAAAAwAAAAIAAAADQAAAHIBAAAYAAAAAgAAAFwAAAACAAAAXQAAACIBAAAWAAAABgAAACQAAAACAAAAJQAAAM4AAAAaAAAABAAAABQAAAAGAAAAFQAAAJ4AAAAcAAAABwAAAA4AAAAEAAAADwAAAKwBAAAaAAAABAAAAGsAAAAAAAAAAAAAAE4BAAAWAAAACAAAACUAAAABAAAAJgAAAPQAAAAYAAAACAAAABQAAAAEAAAAFQAAALQAAAAWAAAADAAAAAsAAAAEAAAADAAAAM0BAAAeAAAAAwAAAHMAAAABAAAAdAAAAG0BAAAYAAAABAAAACgAAAAFAAAAKQAAAAUBAAAUAAAACwAAABAAAAAFAAAAEQAAAMUAAAAYAAAACwAAAAwAAAAFAAAADQAAAAsCAAAWAAAABQAAAFcAAAABAAAAWAAAAJ8BAAAYAAAABQAAACkAAAAFAAAAKgAAACcBAAAeAAAABQAAABgAAAAHAAAAGQAAAN8AAAAYAAAACwAAAAwAAAAHAAAADQAAAE0CAAAYAAAABQAAAGIAAAABAAAAYwAAAMUBAAAcAAAABwAAAC0AAAADAAAALgAAAEUBAAAYAAAADwAAABMAAAACAAAAFAAAAP0AAAAeAAAAAwAAAA8AAAANAAAAEAAAAIcCAAAcAAAAAQAAAGsAAAAFAAAAbAAAAPsBAAAcAAAACgAAAC4AAAABAAAALwAAAG8BAAAcAAAAAQAAABYAAAAPAAAAFwAAABsBAAAcAAAAAgAAAA4AAAARAAAADwAAANECAAAeAAAABQAAAHgAAAABAAAAeQAAADMCAAAaAAAACQAAACsAAAAEAAAALAAAAI0BAAAcAAAAEQAAABYAAAABAAAAFwAAADkBAAAcAAAAAgAAAA4AAAATAAAADwAAABsDAAAcAAAAAwAAAHEAAAAEAAAAcgAAAHMCAAAaAAAAAwAAACwAAAALAAAALQAAAL0BAAAaAAAAEQAAABUAAAAEAAAAFgAAAFUBAAAaAAAACQAAAA0AAAAQAAAADgAAAF0DAAAcAAAAAwAAAGsAAAAFAAAAbAAAAJ0CAAAaAAAAAwAAACkAAAANAAAAKgAAAOUBAAAeAAAADwAAABgAAAAFAAAAGQAAAIEBAAAcAAAADwAAAA8AAAAKAAAAEAAAAKQDAAAcAAAABAAAAHQAAAAEAAAAdQAAAMoCAAAaAAAAEQAAACoAAAAAAAAAAAAAAAACAAAcAAAAEQAAABYAAAAGAAAAFwAAAJYBAAAeAAAAEwAAABAAAAAGAAAAEQAAAO4DAAAcAAAAAgAAAG8AAAAHAAAAcAAAAA4DAAAcAAAAEQAAAC4AAAAAAAAAAAAAADgCAAAeAAAABwAAABgAAAAQAAAAGQAAALoBAAAYAAAAIgAAAA0AAAAAAAAAAAAAAEYEAAAeAAAABAAAAHkAAAAFAAAAegAAAFwDAAAcAAAABAAAAC8AAAAOAAAAMAAAAGYCAAAeAAAACwAAABgAAAAOAAAAGQAAANABAAAeAAAAEAAAAA8AAAAOAAAAEAAAAJYEAAAeAAAABgAAAHUAAAAEAAAAdgAAAJIDAAAcAAAABgAAAC0AAAAOAAAALgAAAJgCAAAeAAAACwAAABgAAAAQAAAAGQAAAAICAAAeAAAAHgAAABAAAAACAAAAEQAAAPwEAAAaAAAACAAAAGoAAAAEAAAAawAAAOgDAAAcAAAACAAAAC8AAAANAAAAMAAAAM4CAAAeAAAABwAAABgAAAAWAAAAGQAAABoCAAAeAAAAFgAAAA8AAAANAAAAEAAAAFoFAAAcAAAACgAAAHIAAAACAAAAcwAAACYEAAAcAAAAEwAAAC4AAAAEAAAALwAAAPICAAAcAAAAHAAAABYAAAAGAAAAFwAAAFQCAAAeAAAAIQAAABAAAAAEAAAAEQAAALwFAAAeAAAACAAAAHoAAAAEAAAAewAAAGgEAAAcAAAAFgAAAC0AAAADAAAALgAAACgDAAAeAAAACAAAABcAAAAaAAAAGAAAAHQCAAAeAAAADAAAAA8AAAAcAAAAEAAAAPsFAAAeAAAAAwAAAHUAAAAKAAAAdgAAAKkEAAAcAAAAAwAAAC0AAAAXAAAALgAAAGcDAAAeAAAABAAAABgAAAAfAAAAGQAAAJUCAAAeAAAACwAAAA8AAAAfAAAAEAAAAF8GAAAeAAAABwAAAHQAAAAHAAAAdQAAAPMEAAAcAAAAFQAAAC0AAAAHAAAALgAAAI8DAAAeAAAA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'
        $null = [System.Reflection.Assembly]::Load([System.Convert]::FromBase64String($content))
        $SyncedVariables.QRGenerationPossible = $true
    } catch {
        Write-Verbose "Error, $($_.Exception.Message)"
        $SyncedVariables.QRGenerationPossible = $false
        #$SyncHash.WPFControl_lblQR.Content = "NOT AVAILABLE!"
        $null = [System.Windows.MessageBox]::Show("Could not load the `"QRCodeGenerator`"!`nQR Code generation is disabled.", "QRCodeGenerator Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Exclamation)
    }
    Write-Verbose "Ending function   : Invoke-LoadQRModule"
}

function Invoke-LoadModules {
    Write-Verbose "Starting function : Get-AdsiADDomain"
    if ($Script:AlternativeLDAPModule) {
        try {
            Write-Verbose "Using Alternative AD Modules"
            if ([String]::IsNullOrEmpty($($SyncHash.WPFControl_tbLDAPServer.Text))) {
                if ($null -eq $SyncedVariables.LDAPCredential -or $SyncedVariables.LDAPCredential -eq [PSCredential]::Empty) {
                    $DNSRoot = Get-AdsiADDomain | Select-Object -ExpandProperty DNSRoot -ErrorAction SilentlyContinue
                    $SyncHash.WPFControl_tbLDAPServer.Text = $DNSRoot
                } else {
                    $DNSRoot = Get-AdsiADDomain -Credential $SyncedVariables.LDAPCredential | Select-Object -ExpandProperty DNSRoot -ErrorAction SilentlyContinue
                    $SyncHash.WPFControl_tbLDAPServer.Text = $DNSRoot
                }
                Write-Verbose "Retrieved the default domain fqdn, $($SyncHash.WPFControl_tbLDAPServer.Text)"
            }
            if ($SyncHash.WPFControl_gbUser.IsEnabled -eq $false) { $SyncHash.WPFControl_gbUser.IsEnabled = $true }
        } catch {
            $SyncHash.WPFControl_tbUsername.Text = "Error while loading Alternative AD Option!"
            Write-Verbose "ERROR: $($_.Exception.Message)"
            if ($SyncHash.WPFControl_gbUser.IsEnabled) { $SyncHash.WPFControl_gbUser.IsEnabled = $false }
            $null = [System.Windows.MessageBox]::Show("Error while loading Alternative AD Option!", "Alternative AD Option", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    } elseif (get-module -ListAvailable  ActiveDirectory -ErrorAction SilentlyContinue) {
        try {
            Write-Verbose "Loading ActiveDirectory Module"
            Import-Module -Name ActiveDirectory -Verbose:$False
            if ([String]::IsNullOrEmpty($($SyncHash.WPFControl_tbLDAPServer.Text))) {
                if ($null -eq $SyncedVariables.LDAPCredential -or $SyncedVariables.LDAPCredential -eq [PSCredential]::Empty) {
                    $DNSRoot = Get-ADDomain -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DNSRoot -ErrorAction SilentlyContinue
                    $SyncHash.WPFControl_tbLDAPServer.Text = $DNSRoot
                } else {
                    $DNSRoot = Get-ADDomain -Credential $SyncedVariables.LDAPCredential -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DNSRoot -ErrorAction SilentlyContinue
                    $SyncHash.WPFControl_tbLDAPServer.Text = $DNSRoot
                }
                Write-Verbose "Retrieved the default domain fqdn, $($SyncHash.WPFControl_tbLDAPServer.Text)"
            }
        } catch {
            $SyncHash.WPFControl_tbUsername.Text = "Error while loading ActiveDirectory Module!"
            if ($SyncHash.WPFControl_gbUser.IsEnabled) { $SyncHash.WPFControl_gbUser.IsEnabled = $false }
            $null = [System.Windows.MessageBox]::Show("Error while loading the `"ActiveDirectory Module`"!`r`nYou can try to set the (experimental) Alt Module option under settings.", "ActiveDirectory Module", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    } else {
        $SyncHash.WPFControl_tbUsername.Text = "ActiveDirectory Module NOT Found!"
        if ($SyncHash.WPFControl_gbUser.IsEnabled) { $SyncHash.WPFControl_gbUser.IsEnabled = $false }
        $null = [System.Windows.MessageBox]::Show("The PowerShell Module `"ActiveDirectory`" was NOT Found!`r`nYou can try to set the (experimental) Alt Module option under settings.", "ActiveDirectory Module", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
    Invoke-LoadQRModule
    Write-Verbose "Ending function   : Get-AdsiADDomain"
}
function Invoke-LoadModulesCL {
    if (get-module -ListAvailable  ActiveDirectory -ErrorAction SilentlyContinue) {
        Write-Verbose "Loading ActiveDirectory Module"
        Import-Module -Name ActiveDirectory -Verbose:$False
    } else {
        Throw "ActiveDirectory Module NOT Found!"
    }
    Invoke-LoadQRModule
}

function Invoke-LoadAppImage {
    Write-Verbose "Starting function : Invoke-LoadAppImage"
    $AppImage = New-Object System.Windows.Media.Imaging.BitmapImage
    $AppImage.BeginInit()
    $AppImage.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($AppImageB64)
    $AppImage.EndInit()
    $AppImage.Freeze()
    $SyncHash.Form.Icon = $AppImage
    $SyncHash.WPFControl_AppImage.Source = $AppImage
    Write-Verbose "Ending function   : Invoke-LoadAppImage"
}

function Invoke-LoadSettings {
    [CmdletBinding()]
    param (
        [String]
        $Path
    )
    Write-Verbose "Starting function : Invoke-LoadSettings"
    if (Test-Path -Path $Path) {
        try {
            $SyncedVariables.Settings = Import-Clixml -Path $Path
            Write-Verbose "Settings loaded!"
        } catch {
            Write-Verbose "Loading failed, $($_.Exception.Message)"
        }
    }
    $SyncHash.WPFControl_tbGatewayURI.Text = $SyncedVariables.Settings.GatewayURI
    $SyncHash.WPFControl_tbQRSize.Text = $SyncedVariables.Settings.QRSize
    $SyncHash.WPFControl_tbLDAPServer.Text = $SyncedVariables.Settings.LDAPSettings.LDAPServer
    $SyncHash.WPFControl_tbLDAPPort.Text = $SyncedVariables.Settings.LDAPSettings.LDAPPort
    if ([String]::IsNullOrEmpty($($SyncHash.WPFControl_tbLDAPPort.Text))) { 
        $SyncHash.WPFControl_tbLDAPPort.Text = "0"
    }
    $SyncHash.WPFControl_tbLDAPUsername.Text = $SyncedVariables.Settings.LDAPSettings.LDAPUsername
    $SyncHash.WPFControl_pbLDAPPassword.Password = try { ConvertTo-PlainText -SecureString $( $SyncedVariables.Settings.LDAPSettings.LDAPPassword ) } catch { $null }
    $SyncHash.WPFControl_tbLDAPAttribute.Text = $SyncedVariables.Settings.LDAPSettings.LDAPAttribute
    $SyncHash.WPFControl_tbAttribute.Text = $SyncedVariables.Settings.LDAPSettings.LDAPAttribute
    $SyncedVariables.Attribute = $SyncedVariables.Settings.LDAPSettings.LDAPAttribute
    if (-Not [String]::IsNullOrEmpty($SyncedVariables.Settings.LDAPSettings.LDAPAlternativeModules)) {
        $SyncHash.WPFControl_cbLDAPAlternativeModule.IsChecked = $SyncedVariables.Settings.LDAPSettings.LDAPAlternativeModules
        $Script:AlternativeLDAPModule = $SyncedVariables.Settings.LDAPSettings.LDAPAlternativeModules
    } else {
        if (-Not ($SyncedVariables.Settings.LDAPSettings | Get-Member -Name LDAPAlternativeModules -ErrorAction SilentlyContinue)) {
            $SyncedVariables.Settings.LDAPSettings | Add-Member -Type NoteProperty -Name LDAPAlternativeModules -Value $false
        }
        $SyncHash.WPFControl_cbLDAPAlternativeModule.IsChecked = $false
        $Script:AlternativeLDAPModule = $false
    }
    if (-Not [String]::IsNullOrEmpty($SyncedVariables.Settings.LDAPSettings.LDAPAttribute)) {
        $Script:Attribute = $SyncedVariables.Settings.LDAPSettings.LDAPAttribute
    }
    if (-Not [String]::IsNullOrEmpty($SyncedVariables.Settings.GatewayURI)) {
        $Script:GatewayURI = $SyncedVariables.Settings.GatewayURI
    }
    if ((-Not [String]::IsNullOrEmpty($($SyncHash.WPFControl_tbLDAPUsername.Text))) -and (-Not [String]::IsNullOrEmpty($($SyncHash.WPFControl_pbLDAPPassword.Password)))) {
        $SyncedVariables.LDAPCredential = try { New-Object System.Management.Automation.PSCredential ($SyncHash.WPFControl_tbLDAPUsername.Text, $(ConvertTo-SecureString $SyncHash.WPFControl_pbLDAPPassword.Password -AsPlainText -Force)) } catch { [PSCredential]::Empty }
    } else {
        $SyncedVariables.LDAPCredential = [PSCredential]::Empty
    }
    $SyncedVariables.Settings.AppVersion = $Script:AppVersion
    Write-Verbose "Ending function   : Invoke-LoadSettings"
}
function ConvertTo-PlainText {
    [CmdletBinding()]
    param    (
        [parameter(Mandatory = $true)]
        [System.Security.SecureString]$SecureString
    )
    Process {
        $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString);
        try {
            $result = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR);
        } finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($BSTR);
            
        }
        return $result
    }
}

function Invoke-SaveSettings {
    [CmdletBinding()]
    param (
        [String]
        $Path
    )
    Write-Verbose "Starting function : Invoke-SaveSettings"
    try {
        $SyncedVariables.Settings.GatewayURI = $SyncHash.WPFControl_tbGatewayURI.Text
        $SyncedVariables.Settings.QRSize = $SyncHash.WPFControl_tbQRSize.Text
        $SyncedVariables.Settings.LDAPSettings.LDAPServer = $SyncHash.WPFControl_tbLDAPServer.Text
        $SyncedVariables.Settings.LDAPSettings.LDAPPort = $SyncHash.WPFControl_tbLDAPPort.Text
        $SyncedVariables.Settings.LDAPSettings.LDAPUsername = $SyncHash.WPFControl_tbLDAPUsername.Text
        $SyncedVariables.Settings.LDAPSettings.LDAPPassword = try { ConvertTo-SecureString -String $($SyncHash.WPFControl_pbLDAPPassword.Password) -AsPlainText -Force -ErrorAction Stop } catch { $null }
        $SyncedVariables.Settings.LDAPSettings.LDAPAttribute = $SyncHash.WPFControl_tbLDAPAttribute.Text
        $SyncedVariables.Settings.LDAPSettings.LDAPAlternativeModules = $SyncHash.WPFControl_cbLDAPAlternativeModule.IsChecked
        $SyncedVariables.Settings.AppVersion = $AppVersion
        Export-CliXml -Path $Path -InputObject $SyncedVariables.Settings -Force
        Update-Gui
        Write-Verbose "Settings saved"
    } catch {
        Write-Verbose "Saving failed, $($_.Exception.Message)"
    }
}

function Invoke-EndApplication {
    [CmdletBinding()]
    param ()
    Write-Verbose "Starting function : Invoke-EndApplication"
    try {
        if ($SyncedVariables.IsGUI) {
            $SyncHash.Form.Close()
            $SyncHash.App.Shutdown()
            try { $PoSH.EndInvoke($SyncedVariables.handle) } catch { }
            $PoSH.RunSpace.Close()
            $RunSpace.Close()
            $RunSpace.Dispose()
            $PoSH.Dispose()
            if (-Not $NoHide) {
                Stop-Process -Id $PID
            } elseif ($Console) {
                # return to console
                [Win32.Functions]::ShowWindow($hWnd, $SW_SHOW)
            }
            Write-Verbose "OTP4ADC Ended!"
            exit $ExitCode
        }
    } catch { "ERROR: $($_.Exception.Message)" } 
}

#region Alternative AD Functions

function Get-AdsiADDomain {
    [CmdletBinding()]
    Param(
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [String]$Server = $SyncedVariables.Settings.LDAPSettings.LDAPServer,

        [Int]$Port = [Int]$SyncedVariables.Settings.LDAPSettings.LDAPPort
    )
    Write-Verbose "Starting function : Get-AdsiADDomain"

    if (-not ($Credential -is [System.Management.Automation.PSCredential])) {
        $Credential = [System.Management.Automation.PSCredential]::Empty
    }
    if (($Credential -eq [System.Management.Automation.PSCredential]::Empty) -and ($SyncedVariables.LDAPCredential -is [System.Management.Automation.PSCredential])) {
        $Credential = $SyncedVariables.LDAPCredential
    }

    $LDAPPath = "LDAP://"
    if ((-Not [String]::IsNullOrEmpty($Server)) -And ($Port -ne 0)) {
        $LDAPPath += "$($Server):$($Port)/"
    } elseif ((-Not [String]::IsNullOrEmpty($Server)) -And ($Port -eq 0)) {
        $LDAPPath += "$($Server)/"
    }
    $LDAPPath += "RootDSE"
    Write-Verbose "Path: `"$LDAPPath`""
    if ($null -eq $Credential -or $Credential -eq [PSCredential]::Empty) { 
        $root = New-Object System.DirectoryServices.DirectoryEntry $LDAPPath
    } else {
        $root = New-Object System.DirectoryServices.DirectoryEntry $LDAPPath, $($Credential.UserName), $($Credential.GetNetworkCredential().password)
        Write-Verbose "Credential was provided"
    }
    try {
        $DistinguishedName = $root | Select-Object -ExpandProperty rootDomainNamingContext
        $DNSRoot = $DistinguishedName -replace "\,(D|d)(C|c)\=", "." -replace "(D|d)(C|c)\=", $null
    } catch {
        $DistinguishedName = $null
        $DNSRoot = $null
    }
    try {
        $DirectoryServer = $root | Select-Object -ExpandProperty dnsHostName

    } catch {
        $DirectoryServer = $null
    }

    Write-Output ([PSCustomObject]@{
            DNSRoot           = $DNSRoot
            DistinguishedName = $DistinguishedName
            DirectoryServer   = $DirectoryServer
        })
    Write-Verbose "Ending function   : Get-AdsiADDomain"
}
        
function Test-AdsiADConnection {
    [CmdletBinding()]
    Param(
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [String]$Server = $SyncedVariables.Settings.LDAPSettings.LDAPServer,

        [Int]$Port = [Int]$SyncedVariables.Settings.LDAPSettings.LDAPPort
    )
    Write-Verbose "Starting function : Test-AdsiADConnection"
    if (-not ($Credential -is [System.Management.Automation.PSCredential])) {
        $Credential = [System.Management.Automation.PSCredential]::Empty
    }
    if (($Credential -eq [System.Management.Automation.PSCredential]::Empty) -and ($SyncedVariables.LDAPCredential -is [System.Management.Automation.PSCredential])) {
        $Credential = $SyncedVariables.LDAPCredential
    }
    try {
        $result = $false
        
        $root = New-Object System.DirectoryServices.DirectoryEntry
        $LDAPPath = "LDAP://"
        Write-Verbose "Server: $Server, Port: $Port"
        if ((-Not [String]::IsNullOrEmpty($Server)) -And ($Port -ne 0)) {
            $LDAPPath += "$($Server):$($Port)/"
        } elseif ((-Not [String]::IsNullOrEmpty($Server)) -And ($Port -eq 0)) {
            $LDAPPath += "$($Server)/"
        }
        $LDAPPath += "RootDSE"
        Write-Verbose "Path: `"$LDAPPath`""
        if ($null -eq $Credential -or $Credential -eq [PSCredential]::Empty) { 
            $root = New-Object System.DirectoryServices.DirectoryEntry $LDAPPath
        } else {
            $root = New-Object System.DirectoryServices.DirectoryEntry $LDAPPath, $($Credential.UserName), $($Credential.GetNetworkCredential().password)
            Write-Verbose "Credential was provided"
        }

        $result = [bool]$root.defaultNamingContext
    } catch {
        Write-Verbose $($_.Exception.Message)
        $result = $false
    }
    Write-Verbose "Ending function   : Test-AdsiADConnection"
    Write-Output $result
}
   
function Get-AdsiADUser {
    [CmdletBinding()]
    Param(
        [String]$Name,
        
        [String[]]$Attributes,
        
        [Int]$SearchLimit = 200,
        
        [String]$SearchBase,
        
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [String]$Server = $SyncedVariables.Settings.LDAPSettings.LDAPServer,

        [Int]$Port = [Int]$SyncedVariables.Settings.LDAPSettings.LDAPPort
        
    )
    Write-Verbose "Starting function : Get-AdsiADUser"
    #Source https://lazywinadmin.com/2013/10/powershell-using-adsi-with-alternate.html
    if (-not ($Credential -is [System.Management.Automation.PSCredential])) {
        $Credential = [System.Management.Automation.PSCredential]::Empty
    }
    if (($Credential -eq [System.Management.Automation.PSCredential]::Empty) -and ($SyncedVariables.LDAPCredential -is [System.Management.Automation.PSCredential])) {
        $Credential = $SyncedVariables.LDAPCredential
    }
    $LDAPPath = "LDAP://"
    if ((-Not [String]::IsNullOrEmpty($Server)) -And ($Port -ne 0)) {
        $LDAPPath += "$($Server):$($Port)/"
    } elseif ((-Not [String]::IsNullOrEmpty($Server)) -And ($Port -eq 0)) {
        $LDAPPath += "$($Server)/"
    }
    if ([String]::IsNullOrEmpty($SearchBase)) {
        $LDAPPath += (Get-AdsiADDomain).DistinguishedName
    } elseif ($SearchBase -like "LDAP://*") {
        $LDAPPath += $SearchBase -replace "LDAP://", $null
    } elseif ($SearchBase -match '(?im)^(?:(?<cn>CN=(?<name>[^,]*)),)?(?:(?<path>(?:(?:CN|OU)=[^,]+,?)+),)?(?<domain>(?:DC=[^,]+,?)+)$') {
        $LDAPPath += $SearchBase
    } else {
        $LDAPPath += (Get-AdsiADDomain).DistinguishedName
    }
    Write-Verbose "Path: `"$LDAPPath`""
    if ($null -eq $Credential -or $Credential -eq [PSCredential]::Empty) { 
        $searchRoot = New-Object System.DirectoryServices.DirectoryEntry $LDAPPath
    } else {
        $searchRoot = New-Object System.DirectoryServices.DirectoryEntry $LDAPPath, $($Credential.UserName), $($Credential.GetNetworkCredential().password)
        Write-Verbose "Credential was provided"
    }
    $adSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher
    $adSearcher.SearchRoot = $searchRoot
    $adSearcher.Filter = "(&(objectCategory=person)(objectClass=user)(|(Name=*$Name*)(UserPrincipalName=*$Name*)(SamAccountName=*$Name*)(Sn=*$Name*)(GivenName=*$Name*)))"
    $adSearcher.SizeLimit = "$SearchLimit"
        
    $Attributes += @("Name", "UserPrincipalName", "SamAccountName", "Sn", "GivenName", "distinguishedName")
    $Attributes = $Attributes | Select-Object -Unique
    foreach ($item in $Attributes) { $adSearcher.PropertiesToLoad.Add($item) | out-null } 
                
    $Users = $adSearcher.FindAll()
    foreach ($User in $Users) {
        Write-Output $(ConvertFrom-HashTable -Collection $User.Properties)
    }
    Write-Verbose "Ending function   : Get-AdsiADUser"
}
    
function Set-AdsiADUser {
    [CmdletBinding()]
    Param(
        [String]$DistinguishedName,
        
        [String]$Attribute,
        
        [String]$NewValue,
        
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [String]$Server = $SyncedVariables.Settings.LDAPSettings.LDAPServer,

        [Int]$Port = [Int]$SyncedVariables.Settings.LDAPSettings.LDAPPort
        
    )
    Write-Verbose "Starting function : Set-AdsiADUser"
    if (-not ($Credential -is [System.Management.Automation.PSCredential])) {
        $Credential = [System.Management.Automation.PSCredential]::Empty
    }
    if (($Credential -eq [System.Management.Automation.PSCredential]::Empty) -and ($SyncedVariables.LDAPCredential -is [System.Management.Automation.PSCredential])) {
        $Credential = $SyncedVariables.LDAPCredential
    }
    $LDAPPath = "LDAP://"
    if ((-Not [String]::IsNullOrEmpty($Server)) -And ($Port -ne 0)) {
        $LDAPPath += "$($Server):$($Port)/"
    } elseif ((-Not [String]::IsNullOrEmpty($Server)) -And ($Port -eq 0)) {
        $LDAPPath += "$($Server)/"
    }

    
    if ($DistinguishedName -like "CN=*") {
        $LDAPPath += $DistinguishedName
    } else {
        $LDAPPath += $DistinguishedName -replace "LDAP://", $null
    }
        
    if ($null -eq $Credential -or $Credential -eq [PSCredential]::Empty) {
        $UserObject = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $LDAPPath
    } else {
        $UserObject = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $LDAPPath, $($Credential.UserName), $($Credential.GetNetworkCredential().password)
        Write-Verbose "Credential was provided"
    }
        
    if ([String]::IsNullOrEmpty($NewValue)) {
        $UserObject.PutEx(1, $Attribute, $null)
    } else {
        $UserObject.$($SyncedVariables.Attribute) = $NewValue
    }
    $UserObject.SetInfo()
    Write-Verbose "Ending function   : Set-AdsiADUser"
}

function ConvertFrom-HashTable {
    [CmdletBinding()]
    param(
        [HashTable]$Collection
    )
    $Object = New-Object PSObject
    foreach ($key in $Collection.keys) {
        $Object | Add-Member -MemberType NoteProperty -Name $key -Value ($Collection.$Key | ForEach-Object { $_ })
    }
    return $Object
}

#endregion Alternative AD Functions


#endregion functions

if ($PsCmdlet.ParameterSetName -eq "CommandLine") {
    Write-Verbose "Running CommandLine mode!"
    $SyncedVariables = [hashtable]::Synchronized(@{ })
    $SyncedVariables.IsGUI = $false
    Invoke-LoadModulesCL    
    $Output = [PSCustomObject]@{
        UserPrincipalName = $null
        NewSecret         = $null
        QRFileName        = $null
        Success           = $false
    }
    if (-Not [String]::IsNullOrEmpty($Username)) {
        $ADUser = Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(|(Name=*$Username*)(UserPrincipalName=*$Username*)(SamAccountName=*$Username*)))" -Properties @($Attribute) | ForEach-Object {
            $Username = $_.SamAccountName
            [PSCustomObject]@{
                SamAccountName    = $Username
                GivenName         = $_.GivenName
                Surname           = $_.Surname
                Name              = $_.Name
                Attribute         = $_."$Attribute"
                DistinguishedName = $_.DistinguishedName
                UserPrincipalName = $_.UserPrincipalName
            }
        }
    } else {
        Throw "No user was found!"
    }

    if ($ADUser.Count -gt 1) {
        Write-Host "Multiple accounts found, please select only one!"
        $ADUser | ForEach-Object {
            Write-Host -ForegroundColor Yellow "Name: $($_.Name)`r`nSAM: $($_.SamAccountName)`r`nUPN: $($_.UserPrincipalName)`r`n"
        }
        Throw "Multiple user accounts found"
    }
    $Output.UserPrincipalName = $ADUser.UserPrincipalName
    Write-Verbose "$($ADUser | Out-String )"

    $DeviceSecrets = @()
    if (-Not $ReplaceTokens) {
        $DeviceSecrets += ConvertFrom-Attribute -Data $ADUser.Attribute
    } else {
        Write-Verbose "ReplaceTokens was specified, overwriting all Tokens for user!"
    }

    if ($DeviceName -in $DeviceSecrets.DeviceName) {
        Throw "Device name `"$DeviceName`" is already in use, specify a unique name! In use: `"$($DeviceSecrets.DeviceName -Join '", "')`""
    }
    
    $Output.NewSecret = Get-OTPSecret

    $DeviceSecrets += [PSCustomObject]@{
        DeviceName = $DeviceName
        Secret     = $Output.NewSecret
    }

    Write-Verbose "$($DeviceSecrets | Out-String )"

    Write-Verbose "$TokenURI"
    try {
        $OTPUri = "otpauth://totp/"
        switch ($TokenText) {
            "1" {
                # username@domain.com
                $OTPUri += [Uri]::EscapeDataString($('{0}' -f $ADUser.UserPrincipalName))
                Break
            }
            "2" {
                #username@gateway.domain.com
                $OTPUri += [Uri]::EscapeDataString($('{0}@{1}' -f $ADUser.SamAccountName, $GatewayURI))
                Break
            }
            "3" {
                #username@domain.com@gateway.domain.com
                $OTPUri += [Uri]::EscapeDataString($('{0}@{1}' -f $ADUser.UserPrincipalName, $GatewayURI ))
                Break
            }
            Default {
                $OTPUri += [Uri]::EscapeDataString($('{0}' -f $ADUser.UserPrincipalName))
                Break
            }
        }
        
        $OTPUri += "?secret={0}&device={1}" -f $Output.NewSecret, $DeviceName
        Write-Verbose "OTP Uri: $OTPUri"
        $QRImage = New-QRTOTPImage -URI $OTPUri -OutStream
    
    } catch {
        $Output.NewSecret = $null
        Write-Output $Output
        Throw "Error while generating QR Image, $($_.Exception.Message)"
    }
    try {
        $DistinguishedName = $ADUser.DistinguishedName
        if ($DeviceSecrets.Count -gt 0) {
            $NewOTP = @()
            ForEach ($Item in $DeviceSecrets) {
                $NewOTP += "{0}={1}" -f $Item.DeviceName, $Item.Secret
            }
            $NewOTPString = "#@$($NewOTP -Join '&,')&,"
            Write-Verbose "New OTP AD User String: `"$NewOTPString`""
            Set-ADUser -Identity $DistinguishedName -Replace @{ "$Attribute" = $NewOTPString } -ErrorAction Stop
        } else {
            Write-Verbose "No OTP for user, save empty string"
            $NewOTPString = $null
            Set-ADUser -Identity $DistinguishedName -Clear @("$Attribute") -ErrorAction Stop
        }
  
    } catch {
        $Output.NewSecret = $null
        Write-Output $Output
        Throw "Error while saving User Attributes, $($_.Exception.Message)"
    }
    try {
        $PNGFileName = Join-Path -Path $ExportPath -ChildPath "$($ADUser.UserPrincipalName)_$($DeviceName).png"
        Write-Verbose "Exporting QR code to `"$PNGFileName`""
        [System.IO.File]::WriteAllBytes($PNGFileName, $($QRImage.ToArray()))
    } catch {
        Write-Output $Output
        Throw "Error while exporting the QR Image, $($_.Exception.Message)"
    }
    $Output.Success = $true
    Write-Verbose "Finished"
    Write-Output $Output
} else {
    #Load Assemblies
    Write-Verbose "Running in GUI mode!"
    Write-Verbose "Load: System.Drawing"
    
    #Add-Type -AssemblyName "System.Drawing"
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
    Write-Verbose "Load: PresentationCore"
    #Add-Type -AssemblyName PresentationCore
    [void] [System.Reflection.Assembly]::LoadWithPartialName("PresentationCore") 
    Write-Verbose "Load: PresentationFramework"
    #Add-Type -AssemblyName PresentationFramework
    [void] [System.Reflection.Assembly]::LoadWithPartialName("PresentationFramework") 
   
    if (-Not $NoHide) {
        $SW_HIDE, $SW_SHOW = 0, 5
        $TypeDef = '[DllImport("User32.dll")]public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);'
        Add-Type -MemberDefinition $TypeDef -Namespace Win32 -Name Functions
        $hWnd = (Get-Process -Id $PID).MainWindowHandle
        $Null = [Win32.Functions]::ShowWindow($hWnd, $SW_HIDE)
    }

    $SyncHash = [hashtable]::Synchronized(@{ })
    $SyncedVariables = [hashtable]::Synchronized(@{ })

    $SyncedVariables.Settings = [PSCustomObject]@{
        AppVersion   = $AppVersion
        GatewayURI   = $GatewayURI
        TokenText    = $TokenText
        QRSize       = $QRSize
        LDAPSettings = [PSCustomObject]@{
            LDAPServer             = $null
            LDAPPort               = $null
            LDAPUsername           = $null
            LDAPPassword           = $null
            LDAPAttribute          = $Attribute
            LDAPAlternativeModules = $false
        }
    }
    $SyncedVariables.IsGUI = $true
    $SyncedVariables.SettingsFilename = Join-Path -Path $env:APPDATA -ChildPath "OTP4ADC\Settings.xml"
    New-Item -Path $(Split-Path -Path $SyncedVariables.SettingsFilename -Parent) -ItemType Directory -Force | Out-Null

    $SyncedVariables.OTPUpdate = $True
    $SyncedVariables.OTPTimeWindow = 30
    $SyncedVariables.OTPLength = 6
    $SyncedVariables.TokenText = "2"
    $SyncedVariables.CleanGUIUser = $false
    $SyncHash.Host = $host
    Write-Verbose "HashTables created"
    $RunSpace = [RunSpaceFactory]::CreateRunspace()
    $RunSpace.Open()
    Write-Verbose "RunSpace : $($RunSpace.RunSpaceStateInfo.State)"
    $RunSpace.SessionStateProxy.SetVariable('SyncHash', $SyncHash)
    $RunSpace.SessionStateProxy.SetVariable('SyncedVariables', $SyncedVariables)
    $PoSH = [powershell]::Create()
    $PoSH.Runspace = $RunSpace
    $PoSH.AddScript( {
            While ($SyncedVariables.OTPUpdate) {
                if ($null -ne $SyncedVariables.OTPToken -and ($SyncedVariables.OTPToken.ValidTo -is [datetime])) {
                    $SecondsLeft = ($SyncedVariables.OTPToken.ValidTo - (Get-Date)).TotalSeconds
                    if ($SecondsLeft -lt 0) {
                        $syncHash.Form.Dispatcher.Invoke(
                            [action] {
                                $SyncHash.WPFControl_tbTOTPToken.Text = "------"
                                $SyncHash.WPFControl_pbTOTPToken.Value = 0
                                $SyncHash.WPFControl_btnViewTOTPToken.Focus()
                                $SyncHash.WPFControl_btnViewTOTPToken.IsEnabled = $true
                                $SyncedVariables.OTPUpdate = $false
                                $SyncedVariables.OTPToken = $null
                            }
                        )
                    } else {
                        $syncHash.Form.Dispatcher.Invoke(
                            [action] {
                                $Progress = [int]($SecondsLeft / $SyncedVariables.OTPTimeWindow * 100)
                                $SyncHash.WPFControl_pbTOTPToken.Value = $Progress
                            }
                        )
                    }
                }
                Start-Sleep -Seconds 1
            }
        }
    ) | Out-Null

    $InputXML = @"
<Window x:Class="OTP4ADC.MainWindow"
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
    xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
    xmlns:local="clr-namespace:OTP4ADC"
    mc:Ignorable="d" 
    Title="OTP4ADC" SizeToContent="WidthAndHeight" ResizeMode="NoResize" Height="Auto" Width="Auto" WindowStartupLocation="CenterOwner">
<Grid Margin="2" >
    <TabControl >
        <TabItem Header="OTP">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <GroupBox Name="gbUser" Grid.Row="0" Grid.Column="0" Grid.RowSpan="2" Header="User" Height="Auto" Margin="2" Width="Auto">
                    <Grid Margin="3">
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Label Name="lblUsername" Grid.Row="0" Grid.Column="0" VerticalContentAlignment="Center" Width="80" Margin="2" Content="Username" />
                        <TextBox Name="tbUsername" Grid.Row="0" Grid.Column="1" VerticalContentAlignment="Center" Margin="2" Text="" Width="320" ToolTip="Enter the Username or part of the username" TabIndex="10" />
                        <Button Name="btnSearch" Grid.Row="0" Grid.Column="2" VerticalContentAlignment="Center" Margin="2" Content="Search" Width="100" Height="Auto" TabIndex="20" ToolTip="Search for user" />
                        <ListView Name="lvUsernames" Grid.Row="1" Grid.Column="1" Grid.RowSpan="2" VerticalContentAlignment="Top" Margin="2" Height="150" Width="320" FontSize="8" SelectionMode="Single" TabIndex="30" >
                            <ListView.View>
                                <GridView>
                                    <GridViewColumn Header="SamAccountName" DisplayMemberBinding="{Binding SamAccountName}" Width="70"/>
                                    <GridViewColumn Header="UPN" DisplayMemberBinding="{Binding UserPrincipalName}" Width="140"/>
                                    <GridViewColumn Header="GivenName" DisplayMemberBinding="{Binding GivenName}" Width="50"/>
                                    <GridViewColumn Header="Surname" DisplayMemberBinding="{Binding Surname}" Width="50"/>
                                </GridView>
                            </ListView.View>
                        </ListView>
                        <Button Name="btnClear" Grid.Row="1" Grid.Column="2" VerticalContentAlignment="Center" Margin="2" Content="Clear" Width="100" VerticalAlignment="Top" Height="27" ToolTip="Clear all settings"  />
                        <Label Name="lblAttribute" Grid.Row="3" Grid.Column="0" VerticalContentAlignment="Top" Margin="2" Content="Attribute" Width="90" />
                        <TextBox Name="tbAttribute" Grid.Row="3" Grid.Column="1" VerticalContentAlignment="Center" Margin="2" Text="" Width="320" ToolTip="Can be pre-configured by starting the application with the -Attribute '&lt;AD Attribute&gt;' parameter, if not configured it uses the default 'userParameters'" />
                        <Label Name="lblOtp" Grid.Row="4" Grid.Column="0" VerticalContentAlignment="Top" Margin="2" Content="OTP" Width="90"  VerticalAlignment="Top"/>
                        <ListView Name="lvOtps" Grid.Row="4" Grid.Column="1" Grid.RowSpan="3" VerticalContentAlignment="Top" Margin="2"  Width="320" FontSize="10" SelectionMode="Single" TabIndex="40" Height="100"  >
                            <ListView.View>
                                <GridView>
                                <GridViewColumn Header="Device Name" DisplayMemberBinding="{Binding DeviceName}" Width="100"/>
                                <GridViewColumn Header="Secret" DisplayMemberBinding="{Binding Secret}" Width="210"/>
                            </GridView>
                            </ListView.View>
                        </ListView>
                        <StackPanel Grid.Row="4" Grid.Column="2" Grid.RowSpan="3" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Margin="0">
                            <Button Name="btnDeleteOtpSecret" VerticalContentAlignment="Center" Margin="2" Content="Delete" Width="100" VerticalAlignment="Top" Height="27" ToolTip="Delete the selected secret" />
                            <Button Name="btnSaveOtp" VerticalContentAlignment="Center" Margin="2" Content="Save" Width="100" VerticalAlignment="Top" Height="27" ToolTip="Save the current secret(s) to the user account" />
                            <Button Name="btnExportPosh" VerticalContentAlignment="Center" Margin="2" Content="Export PoSH" Width="100" VerticalAlignment="Top" Height="27" ToolTip="Export the PowerShell command to make the necessary changes." />
                        </StackPanel>
                    </Grid>
                </GroupBox>
                <GroupBox Grid.Row="0" Grid.Column="1" Grid.RowSpan="2" Header="QR" Height="Auto" Margin="2" Width="Auto">
                    <Grid Margin="3">
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Label Name="lbTokenUserText" Grid.Row="0" Grid.Column="0" Margin="2" Content="" VerticalAlignment="Center" HorizontalContentAlignment="left" VerticalContentAlignment="Center" Width="200" Visibility="Visible" FontWeight="Bold" FontSize="8" />
                        <Image Name="ImgQR" Grid.Row="1" Grid.Column="0" Margin="2" Height="200" Width="200" Visibility="Visible" Stretch="UniformToFill" RenderTransformOrigin="0.5,0.5" />
                        <Label Name="lblQR" Grid.Row="2" Grid.Column="0" Margin="2" Content="" VerticalAlignment="Bottom" HorizontalContentAlignment="Center" VerticalContentAlignment="Center" Visibility="Visible" FontWeight="Bold" FontSize="14"/>
                        <Button Name="btnExportQR" Grid.Row="3" Grid.Column="0" VerticalContentAlignment="Center" Margin="2" Content="Export QR" Width="100" VerticalAlignment="Bottom" Height="27" TabIndex="100" ToolTip="Export and save the QR code" />
                    </Grid>
                </GroupBox>
                <GroupBox Grid.Row="2" Grid.Column="0" Grid.RowSpan="2" Header="OTP Secret" Height="Auto" Margin="2" Width="Auto">
                    <Grid Margin="3">
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Label Name="lblSecret" Grid.Row="0" Grid.Column="0" VerticalContentAlignment="Center" Width="90" Margin="2" Content="Secret" />
                        <TextBox Name="tbSecret" Grid.Row="0" Grid.Column="1" VerticalContentAlignment="Center" Margin="2" Text="" Width="320" IsReadOnly="True" />
                        <Button Name="btnGenerateSecret" Grid.Row="0" Grid.Column="2" VerticalContentAlignment="Center" Margin="2" Content="Generate Secret" Width="100" TabIndex="60" ToolTip="Generate a new secret" />
                        <Label Name="lblDeviceName" Grid.Row="1" Grid.Column="0" VerticalContentAlignment="Center" Width="90" Margin="2" Content="Device Name" />
                        <TextBox Name="tbDeviceName" Grid.Row="1" Grid.Column="1" VerticalContentAlignment="Center" Margin="2" Text="" Width="320" TabIndex="70" />
                        <Button Name="btnAddQR" Grid.Row="1" Grid.Column="2" VerticalContentAlignment="Center" Margin="2" Content="Add" Width="100" ToolTip="Add the generated secret to the user account" />
                        <Label Name="lblGateway" Grid.Row="2" Grid.Column="0" VerticalContentAlignment="Center" Width="90" Margin="2" Content="Gateway fqdn" />
                        <TextBox Name="tbGateway" Grid.Row="2" Grid.Column="1" VerticalContentAlignment="Center" Margin="2" Text="" Width="320" ToolTip="Can be pre-configured by starting the application with the -GatewayUri '&lt;gw.domain.com&gt;' parameter" TabIndex="80" />
                        <Button Name="btnGenerateQR" Grid.Row="2" Grid.Column="2" VerticalContentAlignment="Center" Margin="2" Content="Generate QR" Width="100" VerticalAlignment="Top" Height="27" TabIndex="90" ToolTip="Generate a QR code" />
                        <Label Name="lblTokenDisplayText" Grid.Row="3" Grid.Column="0" VerticalContentAlignment="Center" Width="90" Margin="2" Content="Token Text" />
                        <StackPanel Name="gbTokenText" Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="3" Margin="2" ToolTip="Select a text format for the Authenticator App" IsEnabled="true">
                            <RadioButton Name="rbTokenTextOption1" Content = '[1] username@domain.corp'/>
                            <RadioButton Name="rbTokenTextOption2" Content = '[2] username@gateway.domain.com' IsChecked="True"/>
                            <RadioButton Name="rbTokenTextOption3" Content = '[3] username@domain.corp@gateway.domain.com'/>
                        </StackPanel>
                    </Grid>
                </GroupBox>
                <GroupBox Name="gbToken" Grid.Row="2" Grid.Column="1" Header="Token" Height="Auto" Margin="2" Width="Auto" IsEnabled="False">
                    <Grid Margin="3">
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition />
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <TextBox Name="tbTOTPToken" Grid.Row="0" Grid.Column="0" VerticalContentAlignment="Center" Margin="2" Text="------" Width="Auto" IsReadOnly="True" HorizontalContentAlignment="Center" FontSize="20" FontFamily="Lucida Console" ToolTip="Token code will be copied to the clipboard" />
                        <Button Name="btnViewTOTPToken" Grid.Row="0" Grid.Column="1" VerticalContentAlignment="Center" Margin="2" Content="View Token" Width="100" Height="27" ToolTip="Click to generate a token code" />
                        <ProgressBar Name="pbTOTPToken" Grid.Row="1" Grid.Column="0" Grid.ColumnSpan="2" Height="5" Margin="2"/>
                    </Grid>
                </GroupBox>
                <Image Name="AppImage"  Grid.Column="1"  Grid.Row="3" HorizontalAlignment="Right" Height="100" VerticalAlignment="Bottom" Width="100"/>
            </Grid>
        </TabItem>
        <TabItem Header="Settings">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Row="0" Grid.Column="2" Grid.RowSpan="3" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Margin="0,10,0,0">
                    <Button Name="btnSaveSettings" VerticalContentAlignment="Center" Height="27" Margin="2" Content="Save" Width="100" TabIndex="300" ToolTip="Search for user" VerticalAlignment="Top"/>
                    <Button Name="btnTestSettings" VerticalContentAlignment="Center" Height="27" Margin="2" Content="Test" Width="100" TabIndex="300" ToolTip="Test and validate the settings" VerticalAlignment="Top"/>
                </StackPanel>
                
                <GroupBox Name="gbGeneral" Grid.Row="0" Grid.Column="0" Header="General Settings" Height="Auto" Margin="2" Width="Auto" IsEnabled="True">
                    <Grid Margin="3">
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Label Name="lblGatewayURI" Grid.Row="0" Grid.Column="0" VerticalContentAlignment="Center" Width="80" Margin="2" Content="Gateway URI" />
                        <TextBox Name="tbGatewayURI" Grid.Row="0" Grid.Column="1" VerticalContentAlignment="Center" Margin="2" Text="" Width="320" ToolTip="Enter the Gateway URI / Address" TabIndex="10" />
                        <Label Name="lblQRSize" Grid.Row="1" Grid.Column="0" VerticalContentAlignment="Center" Width="80" Margin="2" Content="QR Size" />
                        <TextBox Name="tbQRSize" Grid.Row="1" Grid.Column="1" VerticalContentAlignment="Center" Margin="2" Text="" Width="320" ToolTip="Enter the QR Image size (default 300x300)" TabIndex="20" />
                    </Grid>
                </GroupBox>
                <GroupBox Name="gbLDAP" Grid.Row="1" Grid.Column="0" Header="LDAP Settings" Height="Auto" Margin="2" Width="Auto" IsEnabled="True" >
                    <Grid Margin="3">
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Label Name="lblLDAPServer" Grid.Row="0" Grid.Column="0" VerticalContentAlignment="Center" Width="80" Margin="2" Content="Server" />
                        <TextBox Name="tbLDAPServer" Grid.Row="0" Grid.Column="1" VerticalContentAlignment="Center" Margin="2" Text="" Width="320" ToolTip="Enter the LDAP server fqdn, ip address or domain fqdn. Leave empty for default value." TabIndex="100" />
                        <Label Name="lblLDAPPort" Grid.Row="1" Grid.Column="0" VerticalContentAlignment="Center" Width="80" Margin="2" Content="Port" />
                        <TextBox Name="tbLDAPPort" Grid.Row="1" Grid.Column="1" VerticalContentAlignment="Center" Margin="2" Text="" Width="320" ToolTip="Enter the LDAP server port, 0 for default. E.g. 636" TabIndex="100" />
                        <Label Name="lblLDAPUsername" Grid.Row="2" Grid.Column="0" VerticalContentAlignment="Center" Width="80" Margin="2" Content="Username" />
                        <TextBox Name="tbLDAPUsername" Grid.Row="2" Grid.Column="1" VerticalContentAlignment="Center" Margin="2" Text="" Width="320" ToolTip="Enter the LDAP username with the required permissions" TabIndex="120" />
                        <Label Name="lblLDAPPassword" Grid.Row="3" Grid.Column="0" VerticalContentAlignment="Center" Width="80" Margin="2" Content="Password" />
                        <PasswordBox Name="pbLDAPPassword" Grid.Row="3" Grid.Column="1" VerticalContentAlignment="Center" Password="" Margin="2" Width="320" ToolTip="Enter the LDAP password for the username" TabIndex="130" />
                        <Label Name="lblLDAPAttribute" Grid.Row="4" Grid.Column="0" VerticalContentAlignment="Center" Width="80" Margin="2" Content="Attribute" />
                        <TextBox Name="tbLDAPAttribute" Grid.Row="4" Grid.Column="1" VerticalContentAlignment="Center" Margin="2" Text="" Width="320" ToolTip="Enter the LDAP attribute name for storing the OTP seed" TabIndex="140" />
                        <Label Name="lblLDAPAlternativeModule" Grid.Row="5" Grid.Column="0" VerticalContentAlignment="Center" Width="80" Margin="2" Content="Alt. Module" />
                        <CheckBox Name="cbLDAPAlternativeModule" Grid.Row="5" Grid.Column="1" VerticalContentAlignment="Center" Margin="2" Content="Experimental option!" ToolTip="When checked the PowerShell module 'ActiveDirectory' will not be used, but an alternative." TabIndex="150"/>
                    </Grid>
                </GroupBox>
            </Grid>
        </TabItem>
    </TabControl>
</Grid>
</Window>
"@

    $AppImageB64 = @"
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
"@

    [XML]$XAML = $InputXML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'

    try {
        $SyncHash.App = [Windows.Application]::new()
        $SyncHash.Form = [Windows.Markup.XamlReader]::Load( (New-Object System.Xml.XmlNodeReader $XAML) )
    } catch {
        Write-Warning "Unable to parse XML, with error: $($Error[0])`n Ensure that there are NO SelectionChanged or TextChanged properties in your TextBoxes (PowerShell cannot process them)"
        throw
    }

    $XAML.SelectNodes("//*[@Name]") | ForEach-Object {
        try {
            #Set-Variable -Name "WPFControl_$($_.Name)" -Value $SyncHash.Form.FindName($_.Name) -ErrorAction Stop
            $SyncHash."WPFControl_$($_.Name)" = $SyncHash.Form.FindName($_.Name)
        } catch {
            throw
        }
    }

    #Global variable, check if changes are saved
    $SyncedVariables.Saved = $true

    #Loading settings from file
    Invoke-LoadSettings -Path $SyncedVariables.SettingsFilename

    #region Event handlers

    $SyncHash.Form.add_Closing( {
            Write-Verbose "GUI Closing"
            Invoke-SaveSettings -Path $SyncedVariables.SettingsFilename
            Invoke-CleanOTPToken
        }
    )

    $SyncHash.Form.add_Loaded( {
            Write-Verbose "GUI Loaded"
        }
    )

    $SyncHash.Form.add_Activated( {
            Write-Verbose "GUI Activated"
            Start-App
        }
    )

    $SyncHash.WPFControl_btnGenerateSecret.Add_Click(
        { # btnGenerateSecret Click Action
            Write-Verbose "btnGenerateSecret Click"
            Update-Gui
            Invoke-CleanGUIQRImage
            $SyncedVariables.B32Secret = Get-OTPSecret
            $SyncHash.WPFControl_tbSecret.Text = $SyncedVariables.B32Secret
            if (-Not $SyncHash.WPFControl_tbDeviceName.IsEnabled) { $SyncHash.WPFControl_tbDeviceName.IsEnabled = $true }
        }
    )

    $SyncHash.WPFControl_btnClear.Add_Click( 
        { # btnClear Click Action
            Write-Verbose "btnClear Click"
            Reset-GUIForm
            Update-Gui
        }
    )

    $SyncHash.WPFControl_btnDeleteOtpSecret.Add_Click( 
        { # btnDeleteOtpSecret Click Action
            Write-Verbose "btnDeleteOtpSecret Click"
            Update-Gui
            $SelectedItem = $SyncHash.WPFControl_lvOtps.SelectedItem
            $SyncedVariables.DeviceSecrets = @($SyncedVariables.DeviceSecrets | Where-Object { $_.Secret -ne $SelectedItem.Secret })
            $SyncHash.WPFControl_lvOtps.ItemsSource = $SyncedVariables.DeviceSecrets
            if (-Not $SyncHash.WPFControl_btnSaveOtp.IsEnabled) { $SyncHash.WPFControl_btnSaveOtp.IsEnabled = $true }
            if (-Not $SyncHash.WPFControl_btnExportPosh.IsEnabled) { $SyncHash.WPFControl_btnExportPosh.IsEnabled = $true }
            $SyncedVariables.Saved = $false
            Invoke-CleanGUIQR
        }
    )

    $SyncHash.WPFControl_btnSaveOtp.Add_Click( 
        { # btnSaveOtp Click Action
            Write-Verbose "btnSaveOtp Click"
            Update-Gui
            Save-OtpToUser
            Invoke-CleanGUIUser
        }
    )

    $SyncHash.WPFControl_btnExportPosh.Add_Click( 
        { # btnExportPosh Click Action
            Write-Verbose "btnExportPosh Click"
            Update-Gui
            Save-OtpToUserExportCommand
            if ($SyncedVariables.Saved) {
                Invoke-CleanGUIUser
            }
        }
    )

    $SyncHash.WPFControl_btnAddQR.Add_Click( 
        { # btnAddQR Click Action
            Write-Verbose "btnAddQR Click"
            Update-Gui
            if ($SyncedVariables.DeviceSecrets.Count -ge 4) {
                $null = [System.Windows.MessageBox]::Show("The maximum of allowed devices reached.`nTo continue remove one device!", "Maximum Reached!", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            } elseif ($SyncedVariables.DeviceSecrets | Where-Object DeviceName -eq $($SyncHash.WPFControl_tbDeviceName.Text)) {
                $null = [System.Windows.MessageBox]::Show("The Device Name `"$($SyncHash.WPFControl_tbDeviceName.Text)`" already exists", "Double Entry!", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            } elseif ($SyncedVariables.DeviceSecrets | Where-Object Secret -eq $($SyncedVariables.B32Secret)) {
                $null = [System.Windows.MessageBox]::Show("The Secret already exists!`nGenerate a new secret", "Double Entry!", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            } else {
                if (-Not $SyncHash.WPFControl_btnSaveOtp.IsEnabled) { $SyncHash.WPFControl_btnSaveOtp.IsEnabled = $true }
                if (-Not $SyncHash.WPFControl_btnExportPosh.IsEnabled) { $SyncHash.WPFControl_btnExportPosh.IsEnabled = $true }
                $SyncedVariables.DeviceSecrets += [PSCustomObject]@{
                    DeviceName = $($SyncHash.WPFControl_tbDeviceName.Text)
                    Secret     = $($SyncedVariables.B32Secret)
                }
                $SyncHash.WPFControl_lvOtps.ItemsSource = $SyncedVariables.DeviceSecrets
            }
            $SyncedVariables.Saved = $false
            Invoke-CleanGUIQR
        }
    )

    $SyncHash.WPFControl_tbUsername.Add_KeyDown{
        param(
            [Parameter(Mandatory)][Object]$sender,
            [Parameter(Mandatory)][Windows.Input.KeyEventArgs]$e
        )
        #Write-Verbose "Sender: $($sender | Out-String)"
        #Write-Verbose "E: $($e | Out-String)"
        if ($e.Key -eq "Return") {
            Write-Verbose "Enter/Return key pressed"
            Update-Gui
            Invoke-SearchADUser
        }
    }

    $SyncHash.WPFControl_tbAttribute.add_TextChanged( 
        { 
            Write-Verbose "tbAttribute Text Changed"
            $SyncedVariables.Attribute = $SyncHash.WPFControl_tbAttribute.Text
            Write-Verbose "New Value: $($SyncedVariables.Attribute) | Saved value: $($SyncedVariables.Settings.LDAPSettings.LDAPAttribute)"
            Invoke-CleanGUIUser
        }
    )

    $SyncHash.WPFControl_tbDeviceName.add_TextChanged( 
        { 
            Write-Verbose "tbDeviceName Text Changed"
            Update-Gui
            Invoke-ValidateAddSecret
            Invoke-ValidateGUIQR
        }
    )

    $SyncHash.WPFControl_tbGateway.add_TextChanged( 
        { 
            Write-Verbose "tbGateway Text Changed"
            Update-Gui
            Invoke-ValidateAddSecret
            Invoke-ValidateGUIQR
            Invoke-UpdateTokenText
        }
    )
    $SyncHash.WPFControl_tbSecret.add_TextChanged( 
        { 
            Write-Verbose "tbSecret Text Changed"
            Update-Gui
            Invoke-ValidateAddSecret
            Invoke-ValidateGUIQR
        }
    )

    $SyncHash.WPFControl_btnSearch.Add_Click( 
        { # btnSearch Click Action
            Write-Verbose "btnSearch Click"
            Update-Gui
            Invoke-SearchADUser
        }
    )

    $SyncHash.WPFControl_lvUsernames.add_SelectionChanged(
        { 
            Write-Verbose "lvUsernames Selection Changed"
            Update-Gui
            Invoke-CleanGUIQR
            $SelectedItem = $SyncHash.WPFControl_lvUsernames.SelectedItem
            if (-Not [String]::IsNullOrEmpty($($SelectedItem.Attribute))) {
                $SyncedVariables.DeviceSecrets = @()
                $SyncedVariables.DeviceSecrets += ConvertFrom-Attribute -Data $SelectedItem.Attribute
                $SyncHash.WPFControl_lvOtps.ItemsSource = $SyncedVariables.DeviceSecrets
                if ($SyncedVariables.DeviceSecrets.Count -eq 1) {
                    $SyncHash.WPFControl_lvOtps.SelectedIndex = 0
                }
                if (-Not $SyncHash.WPFControl_tbDeviceName.IsEnabled) { $SyncHash.WPFControl_tbDeviceName.IsEnabled = $true }
            } else {
                $SyncHash.WPFControl_lvOtps.ItemsSource = $null
                $SyncedVariables.DeviceSecrets = @()
                if ($SyncHash.WPFControl_tbDeviceName.IsEnabled) { $SyncHash.WPFControl_tbDeviceName.IsEnabled = $false }
            }
            if (-Not [String]::IsNullOrEmpty($($SelectedItem.UserPrincipalName))) {
                Invoke-UpdateTokenText
            }
        }
    )

    $SyncHash.WPFControl_lvOtps.add_SelectionChanged(
        { 
            Write-Verbose "lvOtps Selection Changed" 
            Invoke-CleanOTPToken
            Update-Gui
            $SelectedItem = $SyncHash.WPFControl_lvOtps.SelectedItem
            Write-Verbose "Selected item: $SelectedItem"
            if ([String]::IsNullOrEmpty($($SelectedItem.Secret))) {
                if ($SyncHash.WPFControl_btnDeleteOtpSecret.IsEnabled) { $SyncHash.WPFControl_btnDeleteOtpSecret.IsEnabled = $false }
            } else {
                Invoke-CleanGUIQRImage
                if (-Not $SyncHash.WPFControl_btnDeleteOtpSecret.IsEnabled) { $SyncHash.WPFControl_btnDeleteOtpSecret.IsEnabled = $true }
                if (-Not $SyncHash.WPFControl_gbToken.IsEnabled) { $SyncHash.WPFControl_gbToken.IsEnabled = $true }
                $SelectedItem = $SyncHash.WPFControl_lvOtps.SelectedItem
                $SyncHash.WPFControl_tbSecret.Text = $SelectedItem.Secret
                $SyncedVariables.B32Secret = $SelectedItem.Secret
                $SyncHash.WPFControl_tbDeviceName.Text = $SelectedItem.DeviceName
                if (-Not $SyncHash.WPFControl_btnViewTOTPToken.IsEnabled) { $SyncHash.WPFControl_btnViewTOTPToken.IsEnabled = $true }
            }
        }
    )

    $SyncHash.WPFControl_btnGenerateQR.Add_Click(
        { # btnGenerateQR Click Action
            Write-Verbose "btnGenerateQR Click"
            Invoke-CleanGUIQRImage
            if ($SyncedVariables.QRGenerationPossible) {
                Get-GUIQRImage
                Update-Gui
                $SyncedVariables.DeviceName = $SyncHash.WPFControl_tbDeviceName.Text
                
                # Building OTP Token           
                $SyncedVariables.OTPUri = "otpauth://totp/"

                Write-Verbose "Using TokenText ID: $($SyncedVariables.TokenText) with text: `"$($SyncedVariables.SelectedTokenText)`""
                $SyncHash.WPFControl_lbTokenUserText.Content = $SyncedVariables.SelectedTokenText

                $SyncedVariables.OTPUri += [Uri]::EscapeDataString($($SyncedVariables.SelectedTokenText))
                $SyncedVariables.OTPUri += "?secret={0}&device={1}" -f $SyncedVariables.B32Secret, $SyncedVariables.DeviceName
                Write-Verbose "OTP Uri: $($SyncedVariables.OTPUri)"
                $SyncedVariables.QRImage = New-QRTOTPImage -URI $SyncedVariables.OTPUri -OutStream -Width $SyncedVariables.Settings.QRSize
            
                $SyncedVariables.QRImageSource = New-Object System.Windows.Media.Imaging.BitmapImage
                $SyncedVariables.QRImageSource.BeginInit()
                $SyncedVariables.QRImageSource.StreamSource = $SyncedVariables.QRImage
                $SyncedVariables.QRImageSource.EndInit() 
                #$SyncedVariables.QRImageSource.Freeze()
                $SyncHash.WPFControl_ImgQR.Source = $SyncedVariables.QRImageSource
                Show-QR
            } else {
                $null = [System.Windows.MessageBox]::Show("The PowerShell Module `"QRCodeGenerator`" was NOT Found!`nQR Code generation is disabled.", "QRCodeGenerator Module", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Exclamation)
            }
            Update-Gui
        }
    )

    $SyncHash.WPFControl_btnExportQR.Add_Click(
        { # btnExportQR Click Action
            Write-Verbose "btnExportQR Click"
            try {
                $SelectedItem = $SyncHash.WPFControl_lvUsernames.SelectedItem
                $PNGPath = Save-File -FileName $("{0}_{1}_{2}.png" -f $SelectedItem.SamAccountName, $SyncHash.WPFControl_tbDeviceName.text, $SyncHash.WPFControl_tbGateway.text)
                Write-Verbose "PNGPath: $PNGPath"
                if (Test-Path (Split-Path -Path $PNGPath -Parent | Resolve-Path).Path) {
                    [System.IO.File]::WriteAllBytes($PNGPath, $($SyncedVariables.QRImage.ToArray()))
                    $SyncHash.WPFControl_lblQR.Content = "Exported Successfully!"
                } else {
                    $SyncHash.WPFControl_lblQR.Content = "Export Failed!"
                }
            } catch {
                Write-Verbose "$($_.Exception.Message)"
                $SyncHash.WPFControl_lblQR.Content = "Export Failed!"
            }
        }
    )

    $SyncHash.WPFControl_btnViewTOTPToken.Add_Click(
        { # btnViewTOTPToken Click Action
            Write-Verbose "btnViewTOTPToken Click"
            try {
                $SyncedVariables.OTPToken = Get-OTPToken -B32Secret $SyncedVariables.B32Secret -TimeWindow $SyncedVariables.OTPTimeWindow -OTPLength $SyncedVariables.OTPLength
                $SyncHash.WPFControl_tbTOTPToken.Text = $SyncedVariables.OTPToken.OTP
                $SyncHash.WPFControl_tbTOTPToken.SelectAll()
                $SyncHash.WPFControl_tbTOTPToken.Focus()
                try { $SyncedVariables.OTPToken.OTP | clip.exe } catch { }
                $SyncedVariables.OTPUpdate = $true
                $SyncedVariables.handle = $PoSH.BeginInvoke()
                $SyncHash.WPFControl_btnViewTOTPToken.IsEnabled = $false
                Write-Verbose  $SyncedVariables.OTPToken
            } catch {
                Write-Verbose "$($_.Exception.Message)"
            }
        }
    )

    $SyncHash.WPFControl_btnSaveSettings.Add_Click(
        { # btnSaveSettings Click Action
            Write-Verbose "btnSaveSettings Click"
            try {
                Invoke-SaveSettings -Path $SyncedVariables.SettingsFilename
                Invoke-LoadSettings -Path $SyncedVariables.SettingsFilename
                Invoke-LoadModules
                Reset-GUIForm
            } catch {
                Write-Verbose "$($_.Exception.Message)"
            }
        }
    )
    
    $SyncHash.WPFControl_btnTestSettings.Add_Click(
        { # btnTestSettings Click Action
            Write-Verbose "btnTestSettings Click"
            $SyncHash.WPFControl_btnTestSettings.IsEnabled = $false
            $SyncHash.WPFControl_btnTestSettings.Content = "Checking..."
            Update-Gui
            try {
                try {
                    $Credential = New-Object System.Management.Automation.PSCredential ($SyncHash.WPFControl_tbLDAPUsername.Text, $(ConvertTo-SecureString $SyncHash.WPFControl_pbLDAPPassword.Password -AsPlainText -Force))
                } catch {
                    $Credential = [PSCredential]::Empty
                }
                if (Test-AdsiADConnection -Server $SyncHash.WPFControl_tbLDAPServer.Text -Port $SyncHash.WPFControl_tbLDAPPort.Text -Credential $Credential) {
                    $null = [System.Windows.MessageBox]::Show("Test OK!", "Test", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                } else {
                    $null = [System.Windows.MessageBox]::Show("The test failed!", "Test", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                }
                $SyncHash.WPFControl_btnTestSettings.Content = "Test"
                $SyncHash.WPFControl_btnTestSettings.IsEnabled = $true
            } catch {
                Write-Verbose "$($_.Exception.Message)"
            }
        }
    )
    $SyncHash.WPFControl_tbQRSize.Add_TextChanged(
        {
            # tbQRSize Text Changed Event
            # Only allow numbers
            $this.Text = $this.Text -replace '\D', $null
        })

    #TokenText Handler
    [System.Windows.RoutedEventHandler]$Script:TokenTextCheckedEventHandler = {
        Write-Verbose "TokenText Checked Event"
        $SyncedVariables.TokenText = ($_.source.Name -replace 'rbTokenTextOption', $null)
        Invoke-UpdateTokenText
        Write-Verbose $SyncedVariables.TokenText
    }

    $SyncHash.WPFControl_tbLDAPPort.Add_TextChanged(
        {
            # tbLDAPPort Text Changed Event
            # Only allow numbers
            $this.Text = $this.Text -replace '\D', $null
        })

    $SyncHash.WPFControl_gbTokenText.AddHandler(
        [System.Windows.Controls.RadioButton]::CheckedEvent, $TokenTextCheckedEventHandler
    )
    #endregion Event handlers

    #Set Title
    $SyncHash.Form.Title = "OTP4ADC - $AppVersion"
    # Show/Run the App
    $SyncHash.App.Run($SyncHash.Form) | Out-Null
}
Invoke-EndApplication
Write-Verbose "Bye, thank you for using OTP4ADC"