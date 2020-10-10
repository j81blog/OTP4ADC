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
    Version   : v0.3.0
    Author    : John Billekens
    Requires  : PowerShell v5.1 and up
                Permission to change the user (attribute)
.LINK
    https://blog.j81.nl
#>

[CmdletBinding()]
Param(
    [String]$Attribute = "userParameters",
    
    [String]$GatewayURI = "",
    
    [Switch]$NoHide,
    
    [Int]$QRSize = 300,
    
    [Switch]$Console
)

function New-QRCodeURI {
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
        New-QRCodeURI -URI "https://github.com/TobiasPSP/Modules.QRCodeGenerator" -Width 50 -Show -OutPath "$home\Desktop\qr.png"
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
    Write-Verbose "Function: New-QRCodeURI"
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
    if ($OutStream) { return $MemoryStream }
    
}

function Get-OTPSecret {
    [cmdletbinding()]
    param(
        [Int]$Length = 26
    )
    Write-Verbose "Function: Get-OTPSecret"
    #https://support.yubico.com/support/solutions/articles/15000034367-generating-base32-string-examples
    $RNGCrypto = [Security.Cryptography.RNGCryptoServiceProvider]::Create()
    [Byte[]]$x = 1
    for ($secret = ''; $secret.length -lt $Length) {
        $RNGCrypto.GetBytes($x)
        if ([char]$x[0] -clike '[2-7A-Z]') {
            $secret += [char]$x[0]
        }
    }
    return $secret
}
function Convert-B32toByte {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$Value
    )
    Write-Verbose "Function: Convert-B32toByte"
    $Base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $Binary = ""
    $CharacterArray = $Value.ToUpper().ToCharArray()
    foreach ($Character in $CharacterArray) {
        $Binary += [Convert]::ToString($Base32Chars.IndexOf($Character), 2).PadLeft(5, "0")
    }
    for ($i = 0; $i -le ($Binary.Length - 8); $i += 8) {
        [Byte][Convert]::ToInt32($Binary.Substring($i, 8), 2)
    }
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
    Write-Verbose "Function: Get-OTPToken"
    #Unix epoch time in UTC
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
        Write-Verbose "Error: $($_.Exception.Message)"
        return $null
    }
}

function Save-File {
    [CmdletBinding()]
    Param(
        [string]$InitialDirectory = $([System.Environment]::GetFolderPath("mydocuments")),
        
        [String]$FileName,
        
        [String]$Filter = "All files (*.*)| *.*"
    )
    Write-Verbose "Function: Save-File"
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $OpenFileDialog.initialDirectory = $InitialDirectory
    if (-Not [String]::IsNullOrEmpty($FileName)) {
        $OpenFileDialog.FileName = $FileName
    }
    $OpenFileDialog.filter = $Filter
    $OpenFileDialog.ShowDialog() | Out-Null
    Write-Verbose "FilePath: `"$($OpenFileDialog.filename)`""
    return $OpenFileDialog.filename
} 

function ConvertFrom-Attribute {
    [CmdLetBinding()]
    [OutputType('PSCustomObject')]
    param(
        [String]$Data
    )
    Write-Verbose "Function: ConvertFrom-Attribute"

    if ($Data.Length -gt 2) {
        $Result = $Data.Substring(2).Split(',') | ForEach-Object { [PSCustomObject]@{
                DeviceName = $($_.Split('=')[0])
                Secret     = $(($_.Replace('&', '').Split('=')[1]))
            } } | Where-Object { $_.Secret } | Sort-Object DeviceName
    }
    return $Result | Sort-Object DeviceName
}

function Initialize-GUI {
    Write-Verbose "Function: Initialize-GUI"
    $SyncHash.Form.WindowStartupLocation = [System.Windows.WindowStartupLocation]::CenterScreen
    $SyncHash.WPFControl_tbAttribute.Text = $Attribute
    $Script:OTPDevices = [PSCustomObject]@()
    $SyncHash.DeviceSecrets = [PSCustomObject]@()
    Reset-GUIForm
}

function Update-Gui {
    #Fixes the "freeze" problem
    Write-Verbose "Function: Update-Gui"
    # Basically WinForms Application.DoEvents()
    try { $SyncHash.App.Dispatcher.Invoke([Windows.Threading.DispatcherPriority]::Background, [action] { }) } catch { }
}

function Invoke-CleanGUIQRImage {
    Write-Verbose "Function: Invoke-CleanGUIQRImage"
    if ($SyncHash.WPFControl_btnGenerateQR.IsEnabled) { $SyncHash.WPFControl_btnGenerateQR.IsEnabled = $false }
    if ($SyncHash.WPFControl_btnExportQR.IsEnabled) { $SyncHash.WPFControl_btnExportQR.IsEnabled = $false }
    $SyncHash.WPFControl_ImgQR.Source = $null
    #$SyncHash.WPFControl_ImgQR.Visibility = [System.Windows.Visibility]::Hidden
    if ($QRGeneration) { $SyncHash.WPFControl_lblQR.Content = "" }
    $Script:QRImage = $null
    Invoke-ValidateGUIQR
    Invoke-ValidateAddSecret
}

function Get-GUIQRImage {
    Write-Verbose "Function: Get-GUIQRImage"
    Invoke-CleanGUIQRImage
    $SyncHash.WPFControl_lblQR.Content = "Loading QR..."

}

function Show-QR {
    Write-Verbose "Function: Show-QR"
    #$SyncHash.WPFControl_ImgQR.Visibility = [System.Windows.Visibility]::Visible
    $SyncHash.WPFControl_lblQR.Content = ""
    if (-Not $SyncHash.WPFControl_btnExportQR.IsEnabled) { $SyncHash.WPFControl_btnExportQR.IsEnabled = $true }
    $SyncHash.WPFControl_btnExportQR.Focus() | Out-Null
}

function Search-User {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Name,
        
        [String]$Attribute = $SyncHash.Attribute
    )
    Write-Verbose "Function: Search-User"
    try {
        $Results = Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(|(Name=*$Name*)(UserPrincipalName=*$Name*)(SamAccountName=*$Name*)(Sn=*$Name*)(GivenName=*$Name*)))" -Properties @($Attribute) | ForEach-Object {
            $Username = $_.SamAccountName
            [PSCustomObject]@{
                SamAccountName    = $Username
                GivenName         = $_.GivenName
                Surname           = $_.Surname
                Name              = $_.Name
                Attribute         = $_."$Attribute"
                DistinguishedName = $_.DistinguishedName
                UserPrincipalName = $_.UserPrincipalName
                NetBIOSName       = (Get-ADDomain).NetBIOSName | Where-Object { (Get-ADUser $Username) }
            } }
    } catch {
        $null = [System.Windows.MessageBox]::Show("$($_.Exception.Message)", "Error!", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
    return $Results 
}

function Invoke-CleanGUIUser {
    Write-Verbose "Function: Invoke-CleanGUIUser"
    if ($SyncHash.Saved) {
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
        if ($SyncHash.WPFControl_btnDeleteOtp.IsEnabled) { $SyncHash.WPFControl_btnDeleteOtp.IsEnabled = $false }
        if ($SyncHash.WPFControl_btnLoadOtp.IsEnabled) { $SyncHash.WPFControl_btnLoadOtp.IsEnabled = $false }
        if ($SyncHash.WPFControl_btnSaveOtp.IsEnabled) { $SyncHash.WPFControl_btnSaveOtp.IsEnabled = $false }
        if ($SyncHash.WPFControl_btnExportPosh.IsEnabled) { $SyncHash.WPFControl_btnExportPosh.IsEnabled = $false }
        $SyncHash.Saved = $true
        Invoke-CleanGUIQR
        Invoke-CleanTOTPToken
    }
}

function Invoke-CleanTOTPToken {
    $SyncHash.OTPUpdate = $False
    $SyncHash.OTPToken = $null
    try { $PoSH.EndInvoke($handle) } catch { }
    if ($SyncHash.WPFControl_gbToken.IsEnabled) { $SyncHash.WPFControl_gbToken.IsEnabled = $false }
    $SyncHash.WPFControl_tbTOTPToken.Text = "------"
    $SyncHash.WPFControl_pbTOTPToken.Value = 0
}

function Invoke-CleanGUIQR {
    Write-Verbose "Function: Invoke-CleanGUIQR"
    $SyncHash.WPFControl_tbSecret.Text = ""
    $SyncHash.WPFControl_tbDeviceName.Text = ""
    $SyncHash.WPFControl_tbGateway.Text = $GatewayURI
    if ($SyncHash.WPFControl_btnAddQR.IsEnabled) { $SyncHash.WPFControl_btnAddQR.IsEnabled = $false }
    Invoke-CleanGUIQRImage
}

function Reset-GUIForm {
    [CmdLetBinding()]
    param()
    Write-Verbose "Function: Reset-GUIForm"
    Invoke-CleanGUIUser
    $SyncHash.WPFControl_tbUsername.Focus() | Out-Null
}

function Save-OtpToUser {
    Write-Verbose "Function: Save-OtpToUser"
    $SelectedUser = $SyncHash.WPFControl_lvUsernames.SelectedItem
    $DistinguishedName = $SelectedUser.DistinguishedName
    if ($SyncHash.DeviceSecrets.Count -gt 0) {
        $NewOTP = @()
        ForEach ($Item in $SyncHash.DeviceSecrets) {
            $NewOTP += "{0}={1}" -f $Item.DeviceName, $Item.Secret
        }
        $NewOTPString = "#@$($NewOTP -Join '&,')&,"
        Write-Verbose "New OTP AD User String: `"$NewOTPString`""
        #$DeviceName = $SyncHash.WPFControl_tbDeviceName.text
        Set-ADUser -Identity $DistinguishedName -Replace @{ "$Attribute" = $NewOTPString }
    } else {
        Write-Verbose "No OTP for user, save empty string"
        $NewOTPString = $null
        Set-ADUser -Identity $DistinguishedName -Clear @("$Attribute")
    }
    $SyncHash.Saved = $true
}

function Save-OtpToUserExportCommand {
    Write-Verbose "Function: Save-OtpToUserExportCommand"
    $SelectedUser = $SyncHash.WPFControl_lvUsernames.SelectedItem
    $DistinguishedName = $SelectedUser.DistinguishedName
    if ($SyncHash.DeviceSecrets.Count -gt 0) {
        $NewOTP = @()
        ForEach ($Item in $SyncHash.DeviceSecrets) {
            $NewOTP += "{0}={1}" -f $Item.DeviceName, $Item.Secret
        }
        $NewOTPString = "#@$($NewOTP -Join '&,')&,"
        Write-Verbose "New OTP AD User String: `"$NewOTPString`""
        #$DeviceName = $SyncHash.WPFControl_tbDeviceName.text
        $ExportPoSHCommand = 'Set-ADUser -Identity "{0}" -Replace @{{ "{1}" = "{2}" }}' -f $DistinguishedName, $Attribute, $NewOTPString
    } else {
        Write-Verbose "No OTP for user, save empty string"
        $NewOTPString = $null
        $ExportPoSHCommand = 'Set-ADUser -Identity "{0}" -Clear @("{1}")' -f $DistinguishedName, $Attribute
    }
    $ExportPoSHCommand | clip.exe
    $result = [System.Windows.MessageBox]::Show("The PowerShell command to make the necessary changes was copied to the clipboard.`nClean the current screen? Changes are not saved to the selected user unless you run the copied command!", "PowerShell Command", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
    Write-Verbose "Result: $result"
    switch ($result) {
        "Yes" { $SyncHash.Saved = $true }
        "No" { $SyncHash.Saved = $false }
        Default { $SyncHash.Saved = $true }
    }
}

function Save-OtpToUser {
    Write-Verbose "Function: Save-OtpToUser"
    $SelectedUser = $SyncHash.WPFControl_lvUsernames.SelectedItem
    $DistinguishedName = $SelectedUser.DistinguishedName
    if ($SyncHash.DeviceSecrets.Count -gt 0) {
        $NewOTP = @()
        ForEach ($Item in $SyncHash.DeviceSecrets) {
            $NewOTP += "{0}={1}" -f $Item.DeviceName, $Item.Secret
        }
        $NewOTPString = "#@$($NewOTP -Join '&,')&,"
        Write-Verbose "New OTP AD User String: `"$NewOTPString`""
        #$DeviceName = $SyncHash.WPFControl_tbDeviceName.text
        Set-ADUser -Identity $DistinguishedName -Replace @{ "$Attribute" = $NewOTPString }
    } else {
        Write-Verbose "No OTP for user, save empty string"
        $NewOTPString = $null
        Set-ADUser -Identity $DistinguishedName -Clear @("$Attribute")
    }
    $SyncHash.Saved = $true
}


function Invoke-ValidateGUIQR {
    Write-Verbose "Function: Invoke-ValidateGUIQR"
    Update-Gui
    if (([String]::IsNullOrEmpty($($SyncHash.WPFControl_tbGateway.Text))) -or ([String]::IsNullOrEmpty($($SyncHash.WPFControl_tbDeviceName.Text))) -or ([String]::IsNullOrEmpty($($SyncHash.WPFControl_tbSecret.Text)))) {
        if ($SyncHash.WPFControl_btnGenerateQR.IsEnabled) { $SyncHash.WPFControl_btnGenerateQR.IsEnabled = $false }
    } else {
        if (-Not $SyncHash.WPFControl_btnGenerateQR.IsEnabled) { $SyncHash.WPFControl_btnGenerateQR.IsEnabled = $true }
    }
}

function Invoke-ValidateAddSecret {
    Write-Verbose "Function: Invoke-ValidateAddSecret"
    if (([String]::IsNullOrEmpty($($SyncHash.WPFControl_tbDeviceName.Text))) -or ([String]::IsNullOrEmpty($($SyncHash.WPFControl_tbSecret.Text)))) {
        if ($SyncHash.WPFControl_btnAddQR.IsEnabled) { $SyncHash.WPFControl_btnAddQR.IsEnabled = $false }
    } else {
        if (-Not $SyncHash.WPFControl_btnAddQR.IsEnabled) { $SyncHash.WPFControl_btnAddQR.IsEnabled = $true }
    }
}

function Invoke-SearchADUser {
    Write-Verbose "Function: Invoke-SearchADUser"
    if ([String]::IsNullOrEmpty($($SyncHash.WPFControl_tbUsername.Text))) {
        $null = [System.Windows.MessageBox]::Show("The Username field is empty!", "Username Empty", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    } else {
        $Results = Search-User -Name $SyncHash.WPFControl_tbUsername.Text
        $SyncHash.WPFControl_lvUsernames.ItemsSource = @($Results)
        if ($SyncHash.WPFControl_lvUsernames.Items.Count -eq 1) {
            $SyncHash.WPFControl_lvUsernames.SelectedIndex = 0
        }
    }
}

function Start-App {
    if (-Not $Script:AppStarted) {
        Write-Verbose "Function: Start-App"
        try {
            Invoke-LoadModules
            Invoke-LoadAppImage
            Initialize-GUI
            $Script:AppStarted = $true
        } catch { "ERROR: $($_.Exception.Message)" }
    }
}

function Invoke-LoadModules {

    <#
[System.Net.ServicePointManager]::SecurityProtocol = 
    [System.Net.SecurityProtocolType]::Tls13 -bor `
    [System.Net.SecurityProtocolType]::Tls12 -bor `
    [System.Net.SecurityProtocolType]::Tls11

Register-PSRepository -Default -ErrorAction SilentlyContinue
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction SilentlyContinue
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction SilentlyContinue
Install-Module PowerShellGet -RequiredVersion 2.2.4.1 -SkipPublisherCheck
Update-Module powershellget,packagemanagement -force
Set-PSRepository -Name "PSGallery" -InstallationPolicy Untrusted -ErrorAction SilentlyContinue

#>

    if (get-module -ListAvailable  ActiveDirectory -ErrorAction SilentlyContinue) {
        Import-Module -Name ActiveDirectory -Verbose:$False
    } else {
        $SyncHash.WPFControl_tbUsername.Text = "ActiveDirectory Module NOT Found!"
        if ($SyncHash.WPFControl_gbUser.IsEnabled) { $SyncHash.WPFControl_gbUser.IsEnabled = $false }
        $null = [System.Windows.MessageBox]::Show("The PowerShell Module `"ActiveDirectory`" was NOT Found!", "ActiveDirectory Module", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
    
    try {
        if (get-module -ListAvailable QRCodeGenerator -ErrorAction SilentlyContinue) {
            Write-Verbose "Loading Module QRCodeGenerator"
            Import-Module -Name QRCodeGenerator -Verbose:$False -ErrorAction Stop
            $Script:QRGeneration = $true
        } else {
            if (-Not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue | Where-Object Version -ge ([Version]"2.8.5.201"))) {
                Write-Verbose "Trying to install NuGet PackageProvider"
                try {
                    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
                } catch {
                    Write-Verbose "Failed, $($_.Exception.Message)"
                    $Script:QRGeneration = $false
                    #$SyncHash.WPFControl_lblQR.Content = "NOT AVAILABLE!"
                    $null = [System.Windows.MessageBox]::Show("Nuget PackageProvider was NOT Found!`nThis is required to install QRCodeGenerator`nInstall manually or Re-Run As Administrator", "NuGet Not Available", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Exclamation)
                    Throw
                }
            }
            $PSRepository = Get-PSRepository -Name PSGallery -Verbose:$false
            try {
                Write-Verbose "Temporary change PSRepository to Trusted"
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -Verbose:$false
                Write-Verbose "Install Module QRCodeGenerator to all users"
                Install-Module -Name QRCodeGenerator -Scope AllUsers | Out-Null
            } catch {
                Write-Verbose "Failed, $($_.Exception.Message)"
                Write-Verbose "Install Module QRCodeGenerator to Current User only"
                Install-Module -Name QRCodeGenerator -Scope CurrentUser | Out-Null
            }
            Write-Verbose "Reverting PSGallery settings to the original value"
            Set-PSRepository -Name PSGallery -InstallationPolicy $PSRepository.InstallationPolicy -ErrorAction SilentlyContinue -Verbose:$false
            Write-Verbose "Loading Module QRCodeGenerator"
            Import-Module -Name QRCodeGenerator -Verbose:$False -ErrorAction Stop
            $Script:QRGeneration = $true
        }
    } catch {
        Write-Verbose "Error, $($_.Exception.Message)"
        $Script:QRGeneration = $false
        #$SyncHash.WPFControl_lblQR.Content = "NOT AVAILABLE!"
        $null = [System.Windows.MessageBox]::Show("The PowerShell Module `"QRCodeGenerator`" was NOT Found!`nQR Code generation is disabled.", "QRCodeGenerator Module", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Exclamation)
    }
}

function Invoke-LoadAppImage {
    $AppImage = New-Object System.Windows.Media.Imaging.BitmapImage
    $AppImage.BeginInit()
    $AppImage.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($AppImageB64)
    $AppImage.EndInit()
    $AppImage.Freeze()
    $SyncHash.Form.Icon = $AppImage
    $SyncHash.WPFControl_AppImage.Source = $AppImage
}

if (-Not $NoHide) {
    $SW_HIDE, $SW_SHOW = 0, 5
    $TypeDef = '[DllImport("User32.dll")]public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);'
    Add-Type -MemberDefinition $TypeDef -Namespace Win32 -Name Functions
    $hWnd = (Get-Process -Id $PID).MainWindowHandle
    $Null = [Win32.Functions]::ShowWindow($hWnd, $SW_HIDE)
}
<#(2)
   $TypeDef = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);' 
   $asyncwindow = Add-Type -MemberDefinition $TypeDef -name Win32ShowWindowAsync -namespace Win32Functions -PassThru 
   $null = $asyncwindow::ShowWindowAsync((Get-Process -PID $pid).MainWindowHandle, 0) 
#>
#Clear Console Window
#Clear-Host

#Load Assemblies
Write-Verbose "Load: System.Drawing"
Add-Type -AssemblyName "System.Drawing"
Write-Verbose "Load: PresentationCore"
Add-Type -AssemblyName PresentationCore
Write-Verbose "Load: PresentationFramework"
Add-Type -AssemblyName PresentationFramework
#Write-Verbose "Load: WindowsFormsIntegration"
#Add-Type -AssemblyName WindowsFormsIntegration
#Write-Verbose "Load: System.Windows.Forms"
#Add-Type -AssemblyName System.Windows.Forms

$SyncHash = [hashtable]::Synchronized(@{ })
$SyncHash.OTPUpdate = $True
$SyncHash.OTPTimeWindow = 30
$SyncHash.OTPLength = 6
$SyncHash.Host = $host
Write-Verbose "HashTable created"
$RunSpace = [runspacefactory]::CreateRunspace()
$RunSpace.Open()
Write-Verbose "Runspace : $($RunSpace.RunspaceStateInfo.State)"
$RunSpace.SessionStateProxy.SetVariable('SyncHash', $SyncHash)
$PoSH = [powershell]::Create()
$PoSH.Runspace = $RunSpace
$PoSH.AddScript( {
        While ($SyncHash.OTPUpdate) {
            if ($null -ne $SyncHash.OTPToken -and ($SyncHash.OTPToken.ValidTo -is [datetime])) {
                $SecondsLeft = ($SyncHash.OTPToken.ValidTo - (Get-Date)).TotalSeconds
                if ($SecondsLeft -lt 0) {
                    $SyncHash.host.ui.WriteVerboseLine("RS: Token is no longer valid")
                    $syncHash.Form.Dispatcher.Invoke(
                        [action] {
                            $SyncHash.WPFControl_tbTOTPToken.Text = "------"
                            $SyncHash.WPFControl_pbTOTPToken.Value = 0
                            $SyncHash.OTPUpdate = $false
                            $SyncHash.OTPToken = $null
                        }
                    )
                } else {
                    $syncHash.Form.Dispatcher.Invoke(
                        [action] {
                            $Progress = [int]($SecondsLeft / $SyncHash.OTPTimeWindow * 100)
                            $SyncHash.WPFControl_pbTOTPToken.Value = $Progress
                        }
                    )
                }
            }
            Start-Sleep -Seconds 1
        }
    }
) | Out-Null

#[System.Convert]::ToBase64String([system.Text.Encoding]::UTF8.GetBytes($(Get-Content -Path "C:\Users\John.Billekens\stack\Visual Studio\Repo\OTP4ADC\OTP4ADC\OTP4ADC\MainWindow.xaml" -Raw))) | clip.exe
$XAMLDataB64 = @"
PFdpbmRvdyB4OkNsYXNzPSJPVFA0QURDLk1haW5XaW5kb3ciDQogICAgICAgIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbC9wcmVzZW50YXRpb24iDQogICAgICAgIHhtbG5zOng9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sIg0KICAgICAgICB4bWxuczpkPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2V4cHJlc3Npb24vYmxlbmQvMjAwOCINCiAgICAgICAgeG1sbnM6bWM9Imh0dHA6Ly9zY2hlbWFzLm9wZW54bWxmb3JtYXRzLm9yZy9tYXJrdXAtY29tcGF0aWJpbGl0eS8yMDA2Ig0KICAgICAgICB4bWxuczpsb2NhbD0iY2xyLW5hbWVzcGFjZTpPVFA0QURDIg0KICAgICAgICBtYzpJZ25vcmFibGU9ImQiIA0KICAgICAgICBUaXRsZT0iT1RQNEFEQyIgU2l6ZVRvQ29udGVudD0iV2lkdGhBbmRIZWlnaHQiIFJlc2l6ZU1vZGU9Ik5vUmVzaXplIiBIZWlnaHQ9IkF1dG8iIFdpZHRoPSJBdXRvIj4NCiAgICA8R3JpZCBNYXJnaW49IjIiPg0KICAgICAgICA8R3JpZC5Sb3dEZWZpbml0aW9ucz4NCiAgICAgICAgICAgIDxSb3dEZWZpbml0aW9uIEhlaWdodD0iQXV0byIvPg0KICAgICAgICAgICAgPFJvd0RlZmluaXRpb24gSGVpZ2h0PSJBdXRvIi8+DQogICAgICAgICAgICA8Um93RGVmaW5pdGlvbiBIZWlnaHQ9IkF1dG8iLz4NCiAgICAgICAgICAgIDxSb3dEZWZpbml0aW9uIEhlaWdodD0iQXV0byIvPg0KICAgICAgICA8L0dyaWQuUm93RGVmaW5pdGlvbnM+DQogICAgICAgIDxHcmlkLkNvbHVtbkRlZmluaXRpb25zPg0KICAgICAgICAgICAgPENvbHVtbkRlZmluaXRpb24gV2lkdGg9IkF1dG8iLz4NCiAgICAgICAgICAgIDxDb2x1bW5EZWZpbml0aW9uIFdpZHRoPSJBdXRvIi8+DQogICAgICAgIDwvR3JpZC5Db2x1bW5EZWZpbml0aW9ucz4NCiAgICAgICAgPEdyb3VwQm94IE5hbWU9ImdiVXNlciIgR3JpZC5Sb3c9IjAiIEdyaWQuQ29sdW1uPSIwIiBHcmlkLlJvd1NwYW49IjIiIEhlYWRlcj0iVXNlciIgSGVpZ2h0PSJBdXRvIiBNYXJnaW49IjIiIFdpZHRoPSJBdXRvIj4NCiAgICAgICAgICAgIDxHcmlkIE1hcmdpbj0iMyI+DQogICAgICAgICAgICAgICAgPEdyaWQuUm93RGVmaW5pdGlvbnM+DQogICAgICAgICAgICAgICAgICAgIDxSb3dEZWZpbml0aW9uIEhlaWdodD0iQXV0byIvPg0KICAgICAgICAgICAgICAgICAgICA8Um93RGVmaW5pdGlvbiBIZWlnaHQ9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICAgICAgPFJvd0RlZmluaXRpb24gSGVpZ2h0PSJBdXRvIi8+DQogICAgICAgICAgICAgICAgICAgIDxSb3dEZWZpbml0aW9uIEhlaWdodD0iQXV0byIvPg0KICAgICAgICAgICAgICAgICAgICA8Um93RGVmaW5pdGlvbiBIZWlnaHQ9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICAgICAgPFJvd0RlZmluaXRpb24gSGVpZ2h0PSJBdXRvIi8+DQogICAgICAgICAgICAgICAgICAgIDxSb3dEZWZpbml0aW9uIEhlaWdodD0iQXV0byIvPg0KICAgICAgICAgICAgICAgIDwvR3JpZC5Sb3dEZWZpbml0aW9ucz4NCiAgICAgICAgICAgICAgICA8R3JpZC5Db2x1bW5EZWZpbml0aW9ucz4NCiAgICAgICAgICAgICAgICAgICAgPENvbHVtbkRlZmluaXRpb24gV2lkdGg9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICAgICAgPENvbHVtbkRlZmluaXRpb24gV2lkdGg9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICAgICAgPENvbHVtbkRlZmluaXRpb24gV2lkdGg9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICA8L0dyaWQuQ29sdW1uRGVmaW5pdGlvbnM+DQogICAgICAgICAgICAgICAgPExhYmVsIE5hbWU9ImxibFVzZXJuYW1lIiBHcmlkLlJvdz0iMCIgR3JpZC5Db2x1bW49IjAiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBXaWR0aD0iODAiIE1hcmdpbj0iMiIgQ29udGVudD0iVXNlcm5hbWUiIC8+DQogICAgICAgICAgICAgICAgPFRleHRCb3ggTmFtZT0idGJVc2VybmFtZSIgR3JpZC5Sb3c9IjAiIEdyaWQuQ29sdW1uPSIxIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgTWFyZ2luPSIyIiBUZXh0PSIiIFdpZHRoPSIzMjAiIFRvb2xUaXA9IkVudGVyIHRoZSBVc2VybmFtZSBvciBwYXJ0IG9mIHRoZSB1c2VybmFtZSIgVGFiSW5kZXg9IjEwIiAvPg0KICAgICAgICAgICAgICAgIDxCdXR0b24gTmFtZT0iYnRuU2VhcmNoIiBHcmlkLlJvdz0iMCIgR3JpZC5Db2x1bW49IjIiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBNYXJnaW49IjIiIENvbnRlbnQ9IlNlYXJjaCIgV2lkdGg9IjEwMCIgSGVpZ2h0PSJBdXRvIiBUYWJJbmRleD0iMjAiIC8+DQogICAgICAgICAgICAgICAgPExpc3RWaWV3IE5hbWU9Imx2VXNlcm5hbWVzIiBHcmlkLlJvdz0iMSIgR3JpZC5Db2x1bW49IjEiIEdyaWQuUm93U3Bhbj0iMiIgVmVydGljYWxDb250ZW50QWxpZ25tZW50PSJUb3AiIE1hcmdpbj0iMiIgSGVpZ2h0PSIxNTAiIFdpZHRoPSIzMjAiIEZvbnRTaXplPSI4IiBTZWxlY3Rpb25Nb2RlPSJTaW5nbGUiIFRhYkluZGV4PSIzMCIgPg0KICAgICAgICAgICAgICAgICAgICA8TGlzdFZpZXcuVmlldz4NCiAgICAgICAgICAgICAgICAgICAgICAgIDxHcmlkVmlldz4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8R3JpZFZpZXdDb2x1bW4gSGVhZGVyPSJTYW1BY2NvdW50TmFtZSIgRGlzcGxheU1lbWJlckJpbmRpbmc9IntCaW5kaW5nIFNhbUFjY291bnROYW1lfSIgLz4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8R3JpZFZpZXdDb2x1bW4gSGVhZGVyPSJVUE4iIERpc3BsYXlNZW1iZXJCaW5kaW5nPSJ7QmluZGluZyBVc2VyUHJpbmNpcGFsTmFtZX0iIC8+DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgPEdyaWRWaWV3Q29sdW1uIEhlYWRlcj0iR2l2ZW5OYW1lIiBEaXNwbGF5TWVtYmVyQmluZGluZz0ie0JpbmRpbmcgR2l2ZW5OYW1lfSIgLz4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8R3JpZFZpZXdDb2x1bW4gSGVhZGVyPSJTdXJuYW1lIiBEaXNwbGF5TWVtYmVyQmluZGluZz0ie0JpbmRpbmcgU3VybmFtZX0iIC8+DQogICAgICAgICAgICAgICAgICAgICAgICA8L0dyaWRWaWV3Pg0KICAgICAgICAgICAgICAgICAgICA8L0xpc3RWaWV3LlZpZXc+DQoNCiAgICAgICAgICAgICAgICA8L0xpc3RWaWV3Pg0KDQogICAgICAgICAgICAgICAgPEJ1dHRvbiBOYW1lPSJidG5DbGVhciIgR3JpZC5Sb3c9IjEiIEdyaWQuQ29sdW1uPSIyIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgTWFyZ2luPSIyIiBDb250ZW50PSJDbGVhciIgV2lkdGg9IjEwMCIgVmVydGljYWxBbGlnbm1lbnQ9IlRvcCIgSGVpZ2h0PSIyNyIgIC8+DQoNCiAgICAgICAgICAgICAgICA8TGFiZWwgTmFtZT0ibGJsQXR0cmlidXRlIiBHcmlkLlJvdz0iMyIgR3JpZC5Db2x1bW49IjAiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iVG9wIiBNYXJnaW49IjIiIENvbnRlbnQ9IkF0dHJpYnV0ZSIgV2lkdGg9IjkwIiAvPg0KICAgICAgICAgICAgICAgIDxUZXh0Qm94IE5hbWU9InRiQXR0cmlidXRlIiBHcmlkLlJvdz0iMyIgR3JpZC5Db2x1bW49IjEiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBNYXJnaW49IjIiIFRleHQ9IiIgV2lkdGg9IjMyMCIgVG9vbFRpcD0iQ2FuIGJlIHByZS1jb25maWd1cmVkIGJ5IHN0YXJ0aW5nIHRoZSBhcHBsaWNhdGlvbiB3aXRoIHRoZSAtQXR0cmlidXRlICcmbHQ7QUQgQXR0cmlidXRlJmd0OycgcGFyYW1ldGVyLCBpZiBub3QgY29uZmlndXJlZCBpdCB1c2VzIHRoZSBkZWZhdWx0ICd1c2VyUGFyYW1ldGVycyciIC8+DQogICAgICAgICAgICAgICAgPExhYmVsIE5hbWU9ImxibE90cCIgR3JpZC5Sb3c9IjQiIEdyaWQuQ29sdW1uPSIwIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IlRvcCIgTWFyZ2luPSIyIiBDb250ZW50PSJPVFAiIFdpZHRoPSI5MCIgIFZlcnRpY2FsQWxpZ25tZW50PSJUb3AiLz4NCiAgICAgICAgICAgICAgICA8TGlzdFZpZXcgTmFtZT0ibHZPdHBzIiBHcmlkLlJvdz0iNCIgR3JpZC5Db2x1bW49IjEiIEdyaWQuUm93U3Bhbj0iMyIgVmVydGljYWxDb250ZW50QWxpZ25tZW50PSJUb3AiIE1hcmdpbj0iMiIgIFdpZHRoPSIzMjAiIEZvbnRTaXplPSI4IiBTZWxlY3Rpb25Nb2RlPSJTaW5nbGUiIEhlaWdodD0iQXV0byIgVGFiSW5kZXg9IjQwIiAgPg0KICAgICAgICAgICAgICAgICAgICA8TGlzdFZpZXcuVmlldz4NCiAgICAgICAgICAgICAgICAgICAgICAgIDxHcmlkVmlldz4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8R3JpZFZpZXdDb2x1bW4gSGVhZGVyPSJEZXZpY2UgTmFtZSIgV2lkdGg9IkF1dG8iIERpc3BsYXlNZW1iZXJCaW5kaW5nPSJ7QmluZGluZyBEZXZpY2VOYW1lfSIgLz4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8R3JpZFZpZXdDb2x1bW4gSGVhZGVyPSJTZWNyZXQiIFdpZHRoPSJBdXRvIiBEaXNwbGF5TWVtYmVyQmluZGluZz0ie0JpbmRpbmcgU2VjcmV0fSIgLz4NCiAgICAgICAgICAgICAgICAgICAgICAgIDwvR3JpZFZpZXc+DQogICAgICAgICAgICAgICAgICAgIDwvTGlzdFZpZXcuVmlldz4NCiAgICAgICAgICAgICAgICA8L0xpc3RWaWV3Pg0KICAgICAgICAgICAgICAgIDxTdGFja1BhbmVsIEdyaWQuUm93PSI0IiBHcmlkLkNvbHVtbj0iMiIgR3JpZC5Sb3dTcGFuPSIzIiBIb3Jpem9udGFsQWxpZ25tZW50PSJTdHJldGNoIiBWZXJ0aWNhbEFsaWdubWVudD0iU3RyZXRjaCIgTWFyZ2luPSIxIj4NCiAgICAgICAgICAgICAgICAgICAgPEJ1dHRvbiBOYW1lPSJidG5EZWxldGVPdHAiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBNYXJnaW49IjIiIENvbnRlbnQ9IkRlbGV0ZSIgV2lkdGg9IjEwMCIgVmVydGljYWxBbGlnbm1lbnQ9IlRvcCIgSGVpZ2h0PSIyNyIgLz4NCiAgICAgICAgICAgICAgICAgICAgPEJ1dHRvbiBOYW1lPSJidG5TYXZlT3RwIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgTWFyZ2luPSIyIiBDb250ZW50PSJTYXZlIiBXaWR0aD0iMTAwIiBWZXJ0aWNhbEFsaWdubWVudD0iVG9wIiBIZWlnaHQ9IjI3IiAvPg0KICAgICAgICAgICAgICAgICAgICA8QnV0dG9uIE5hbWU9ImJ0bkV4cG9ydFBvc2giIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBNYXJnaW49IjIiIENvbnRlbnQ9IkV4cG9ydCBQb1NIIiBXaWR0aD0iMTAwIiBWZXJ0aWNhbEFsaWdubWVudD0iVG9wIiBIZWlnaHQ9IjI3IiBUb29sVGlwPSJFeHBvcnQgdGhlIFBvd2VyU2hlbGwgY29tbWFuZCB0byBtYWtlIHRoZSBuZWNlc3NhcnkgY2hhbmdlcy4iIC8+DQogICAgICAgICAgICAgICAgICAgIDxCdXR0b24gTmFtZT0iYnRuTG9hZE90cCIgVmVydGljYWxDb250ZW50QWxpZ25tZW50PSJDZW50ZXIiIE1hcmdpbj0iMiIgQ29udGVudD0iTG9hZCIgV2lkdGg9IjEwMCIgVmVydGljYWxBbGlnbm1lbnQ9IlRvcCIgSGVpZ2h0PSIyNyIgVGFiSW5kZXg9IjUwIiAvPg0KICAgICAgICAgICAgICAgIDwvU3RhY2tQYW5lbD4NCiAgICAgICAgICAgICAgICANCiAgICAgICAgICAgIDwvR3JpZD4NCiAgICAgICAgPC9Hcm91cEJveD4NCiAgICAgICAgPEdyb3VwQm94IEdyaWQuUm93PSIwIiBHcmlkLkNvbHVtbj0iMSIgSGVhZGVyPSJRUiIgSGVpZ2h0PSJBdXRvIiBNYXJnaW49IjIiIFdpZHRoPSJBdXRvIj4NCiAgICAgICAgICAgIDxHcmlkIE1hcmdpbj0iMyI+DQogICAgICAgICAgICAgICAgPEdyaWQuUm93RGVmaW5pdGlvbnM+DQogICAgICAgICAgICAgICAgICAgIDxSb3dEZWZpbml0aW9uIEhlaWdodD0iQXV0byIvPg0KICAgICAgICAgICAgICAgICAgICA8Um93RGVmaW5pdGlvbiBIZWlnaHQ9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICAgICAgPFJvd0RlZmluaXRpb24gSGVpZ2h0PSJBdXRvIi8+DQogICAgICAgICAgICAgICAgPC9HcmlkLlJvd0RlZmluaXRpb25zPg0KICAgICAgICAgICAgICAgIDxHcmlkLkNvbHVtbkRlZmluaXRpb25zPg0KICAgICAgICAgICAgICAgICAgICA8Q29sdW1uRGVmaW5pdGlvbiBXaWR0aD0iQXV0byIvPg0KICAgICAgICAgICAgICAgIDwvR3JpZC5Db2x1bW5EZWZpbml0aW9ucz4NCiAgICAgICAgICAgICAgICA8SW1hZ2UgTmFtZT0iSW1nUVIiIEdyaWQuUm93PSIwIiBHcmlkLkNvbHVtbj0iMCIgTWFyZ2luPSIyIiBIZWlnaHQ9IjIwMCIgV2lkdGg9IjIwMCIgVmlzaWJpbGl0eT0iVmlzaWJsZSIgU3RyZXRjaD0iVW5pZm9ybVRvRmlsbCIgUmVuZGVyVHJhbnNmb3JtT3JpZ2luPSIwLjUsMC41IiAvPg0KICAgICAgICAgICAgICAgIDxMYWJlbCBOYW1lPSJsYmxRUiIgR3JpZC5Sb3c9IjEiIEdyaWQuQ29sdW1uPSIwIiBNYXJnaW49IjIiIENvbnRlbnQ9IiIgVmVydGljYWxBbGlnbm1lbnQ9IkJvdHRvbSIgSG9yaXpvbnRhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgVmVydGljYWxDb250ZW50QWxpZ25tZW50PSJDZW50ZXIiIFZpc2liaWxpdHk9IlZpc2libGUiIEZvbnRXZWlnaHQ9IkJvbGQiIEZvbnRTaXplPSIxNiIvPg0KICAgICAgICAgICAgICAgIDxCdXR0b24gTmFtZT0iYnRuRXhwb3J0UVIiIEdyaWQuUm93PSIyIiBHcmlkLkNvbHVtbj0iMCIgVmVydGljYWxDb250ZW50QWxpZ25tZW50PSJDZW50ZXIiIE1hcmdpbj0iMiIgQ29udGVudD0iRXhwb3J0IFFSIiBXaWR0aD0iMTAwIiBWZXJ0aWNhbEFsaWdubWVudD0iQm90dG9tIiBIZWlnaHQ9IjI3IiBUYWJJbmRleD0iMTAwIiAvPg0KICAgICAgICAgICAgPC9HcmlkPg0KICAgICAgICA8L0dyb3VwQm94Pg0KICAgICAgICA8R3JvdXBCb3ggR3JpZC5Sb3c9IjIiIEdyaWQuQ29sdW1uPSIwIiBIZWFkZXI9IlRPVFAiIEhlaWdodD0iQXV0byIgTWFyZ2luPSIyIiBXaWR0aD0iQXV0byI+DQogICAgICAgICAgICA8R3JpZCBNYXJnaW49IjMiPg0KICAgICAgICAgICAgICAgIDxHcmlkLlJvd0RlZmluaXRpb25zPg0KICAgICAgICAgICAgICAgICAgICA8Um93RGVmaW5pdGlvbiBIZWlnaHQ9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICAgICAgPFJvd0RlZmluaXRpb24gSGVpZ2h0PSJBdXRvIi8+DQogICAgICAgICAgICAgICAgICAgIDxSb3dEZWZpbml0aW9uIEhlaWdodD0iQXV0byIvPg0KICAgICAgICAgICAgICAgIDwvR3JpZC5Sb3dEZWZpbml0aW9ucz4NCiAgICAgICAgICAgICAgICA8R3JpZC5Db2x1bW5EZWZpbml0aW9ucz4NCiAgICAgICAgICAgICAgICAgICAgPENvbHVtbkRlZmluaXRpb24gV2lkdGg9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICAgICAgPENvbHVtbkRlZmluaXRpb24gV2lkdGg9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICAgICAgPENvbHVtbkRlZmluaXRpb24gV2lkdGg9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICA8L0dyaWQuQ29sdW1uRGVmaW5pdGlvbnM+DQogICAgICAgICAgICAgICAgPExhYmVsIE5hbWU9ImxibFNlY3JldCIgR3JpZC5Sb3c9IjAiIEdyaWQuQ29sdW1uPSIwIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgV2lkdGg9IjkwIiBNYXJnaW49IjIiIENvbnRlbnQ9IlNlY3JldCIgLz4NCiAgICAgICAgICAgICAgICA8VGV4dEJveCBOYW1lPSJ0YlNlY3JldCIgR3JpZC5Sb3c9IjAiIEdyaWQuQ29sdW1uPSIxIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgTWFyZ2luPSIyIiBUZXh0PSIiIFdpZHRoPSIzMjAiIElzUmVhZE9ubHk9IlRydWUiIC8+DQogICAgICAgICAgICAgICAgPEJ1dHRvbiBOYW1lPSJidG5HZW5lcmF0ZVNlY3JldCIgR3JpZC5Sb3c9IjAiIEdyaWQuQ29sdW1uPSIyIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgTWFyZ2luPSIyIiBDb250ZW50PSJHZW5lcmF0ZSBTZWNyZXQiIFdpZHRoPSIxMDAiIFRhYkluZGV4PSI2MCIgLz4NCiAgICAgICAgICAgICAgICA8TGFiZWwgTmFtZT0ibGJsRGV2aWNlTmFtZSIgR3JpZC5Sb3c9IjEiIEdyaWQuQ29sdW1uPSIwIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgV2lkdGg9IjkwIiBNYXJnaW49IjIiIENvbnRlbnQ9IkRldmljZSBOYW1lIiAvPg0KICAgICAgICAgICAgICAgIDxUZXh0Qm94IE5hbWU9InRiRGV2aWNlTmFtZSIgR3JpZC5Sb3c9IjEiIEdyaWQuQ29sdW1uPSIxIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgTWFyZ2luPSIyIiBUZXh0PSIiIFdpZHRoPSIzMjAiIFRhYkluZGV4PSI3MCIgLz4NCiAgICAgICAgICAgICAgICA8QnV0dG9uIE5hbWU9ImJ0bkFkZFFSIiBHcmlkLlJvdz0iMSIgR3JpZC5Db2x1bW49IjIiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBNYXJnaW49IjIiIENvbnRlbnQ9IkFkZCIgV2lkdGg9IjEwMCIgLz4NCiAgICAgICAgICAgICAgICA8TGFiZWwgTmFtZT0ibGJsR2F0ZXdheSIgR3JpZC5Sb3c9IjIiIEdyaWQuQ29sdW1uPSIwIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgV2lkdGg9IjkwIiBNYXJnaW49IjIiIENvbnRlbnQ9IkdhdGV3YXkgZnFkbiIgLz4NCiAgICAgICAgICAgICAgICA8VGV4dEJveCBOYW1lPSJ0YkdhdGV3YXkiIEdyaWQuUm93PSIyIiBHcmlkLkNvbHVtbj0iMSIgVmVydGljYWxDb250ZW50QWxpZ25tZW50PSJDZW50ZXIiIE1hcmdpbj0iMiIgVGV4dD0iIiBXaWR0aD0iMzIwIiBUb29sVGlwPSJDYW4gYmUgcHJlLWNvbmZpZ3VyZWQgYnkgc3RhcnRpbmcgdGhlIGFwcGxpY2F0aW9uIHdpdGggdGhlIC1HYXRld2F5VXJpICcmbHQ7Z3cuZG9tYWluLmNvbSZndDsnIHBhcmFtZXRlciIgVGFiSW5kZXg9IjgwIiAvPg0KICAgICAgICAgICAgICAgIDxCdXR0b24gTmFtZT0iYnRuR2VuZXJhdGVRUiIgR3JpZC5Sb3c9IjIiIEdyaWQuQ29sdW1uPSIyIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgTWFyZ2luPSIyIiBDb250ZW50PSJHZW5lcmF0ZSBRUiIgV2lkdGg9IjEwMCIgVmVydGljYWxBbGlnbm1lbnQ9IlRvcCIgSGVpZ2h0PSIyNyIgVGFiSW5kZXg9IjkwIiAvPg0KICAgICAgICAgICAgPC9HcmlkPg0KICAgICAgICA8L0dyb3VwQm94Pg0KICAgICAgICA8R3JvdXBCb3ggTmFtZT0iZ2JUb2tlbiIgR3JpZC5Sb3c9IjEiIEdyaWQuQ29sdW1uPSIxIiBIZWFkZXI9IlRva2VuIiBIZWlnaHQ9IkF1dG8iIE1hcmdpbj0iMiIgV2lkdGg9IkF1dG8iIElzRW5hYmxlZD0iRmFsc2UiPg0KICAgICAgICAgICAgPEdyaWQgTWFyZ2luPSIzIj4NCiAgICAgICAgICAgICAgICA8R3JpZC5Sb3dEZWZpbml0aW9ucz4NCiAgICAgICAgICAgICAgICAgICAgPFJvd0RlZmluaXRpb24gSGVpZ2h0PSJBdXRvIi8+DQogICAgICAgICAgICAgICAgICAgIDxSb3dEZWZpbml0aW9uIEhlaWdodD0iQXV0byIvPg0KICAgICAgICAgICAgICAgIDwvR3JpZC5Sb3dEZWZpbml0aW9ucz4NCiAgICAgICAgICAgICAgICA8R3JpZC5Db2x1bW5EZWZpbml0aW9ucz4NCiAgICAgICAgICAgICAgICAgICAgPENvbHVtbkRlZmluaXRpb24gLz4NCiAgICAgICAgICAgICAgICAgICAgPENvbHVtbkRlZmluaXRpb24gV2lkdGg9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICA8L0dyaWQuQ29sdW1uRGVmaW5pdGlvbnM+DQogICAgICAgICAgICAgICAgPFRleHRCb3ggTmFtZT0idGJUT1RQVG9rZW4iIEdyaWQuUm93PSIwIiBHcmlkLkNvbHVtbj0iMCIgVmVydGljYWxDb250ZW50QWxpZ25tZW50PSJDZW50ZXIiIE1hcmdpbj0iMiIgVGV4dD0iLS0tLS0tIiBXaWR0aD0iQXV0byIgSXNSZWFkT25seT0iVHJ1ZSIgSG9yaXpvbnRhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgRm9udFNpemU9IjIwIiBGb250RmFtaWx5PSJMdWNpZGEgQ29uc29sZSIgLz4NCiAgICAgICAgICAgICAgICA8QnV0dG9uIE5hbWU9ImJ0blZpZXdUT1RQVG9rZW4iIEdyaWQuUm93PSIwIiBHcmlkLkNvbHVtbj0iMSIgVmVydGljYWxDb250ZW50QWxpZ25tZW50PSJDZW50ZXIiIE1hcmdpbj0iMiIgQ29udGVudD0iVmlldyBUb2tlbiIgV2lkdGg9IjEwMCIgSGVpZ2h0PSIyNyIgLz4NCiAgICAgICAgICAgICAgICA8UHJvZ3Jlc3NCYXIgTmFtZT0icGJUT1RQVG9rZW4iIEdyaWQuUm93PSIxIiBHcmlkLkNvbHVtbj0iMCIgR3JpZC5Db2x1bW5TcGFuPSIyIiBIZWlnaHQ9IjUiIE1hcmdpbj0iMiIvPg0KICAgICAgICAgICAgPC9HcmlkPg0KICAgICAgICA8L0dyb3VwQm94Pg0KICAgICAgICA8SW1hZ2UgTmFtZT0iQXBwSW1hZ2UiICBHcmlkLkNvbHVtbj0iMSIgIEdyaWQuUm93PSIyIiBIb3Jpem9udGFsQWxpZ25tZW50PSJSaWdodCIgSGVpZ2h0PSIxMDAiIFZlcnRpY2FsQWxpZ25tZW50PSJCb3R0b20iIFdpZHRoPSIxMDAiLz4NCiAgICA8L0dyaWQ+DQo8L1dpbmRvdz4NCg==
"@
# [Convert]::ToBase64String(($QRImage.ToArray())) | clip.exe
$AppImageB64 = @"
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
"@

$InputXML = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($XAMLDataB64))
[XML]$XAML = $InputXML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'

try {
    #$App = [Windows.Application]::new()
    #$Form = [Windows.Markup.XamlReader]::Load( [Xml.XmlNodeReader]::new($XAML) )
    $SyncHash.App = [Windows.Application]::new()
    $SyncHash.Form = [Windows.Markup.XamlReader]::Load( (New-Object System.Xml.XmlNodeReader $XAML) )
} catch {
    Write-Warning "Unable to parse XML, with error: $($Error[0])`n Ensure that there are NO SelectionChanged or TextChanged properties in your textboxes (PowerShell cannot process them)"
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

Write-Verbose "Defining intractable elements"
#All WPF GUI variables
#$Controls = Get-Variable WPFControl_*

#Global variable, check if changes are saved
$SyncHash.Saved = $true

#region Event handlers

#System.ComponentModel.CancelEventHandler Closing(System.Object, System.ComponentModel.CancelEventArgs)
$SyncHash.Form.add_Closing( {
        Write-Verbose "GUI Closing"
        try {
            Invoke-CleanGUIQRImage
            $SyncHash.Form.Close()
            $SyncHash.App.Shutdown()
            $SyncHash.App.Exit()
            if (-Not $NoHide) {
                Stop-Process -Id $PID 
            } elseif ($Console) {
                # return to console
                [Win32.Functions]::ShowWindow($hWnd, $SW_SHOW)
            }
        } catch { "ERROR: $($_.Exception.Message)" } 
    }
)

#System.EventHandler Initialized(System.Object, System.EventArgs)
#System.EventHandler Activated(System.Object, System.EventArgs)

$SyncHash.Form.add_Loaded( {
        Write-Verbose "GUI Loaded"
    }
)

$SyncHash.Form.add_Activated( {
        Write-Verbose "GUI Activated"
        Start-App
    }
)

#System.Windows.DependencyPropertyChangedEventHandler IsVisibleChanged(System.Object, System.Windows.DependencyPropertyChangedEventArgs)

$SyncHash.WPFControl_btnGenerateSecret.Add_Click( { # btnGenerateSecret Click Action
        Update-Gui
        Invoke-CleanGUIQRImage
        $SyncHash.B32Secret = Get-OTPSecret
        #$SyncHash.B32Secret = New-AuthenticatorSecret
        $SyncHash.WPFControl_tbSecret.Text = $SyncHash.B32Secret
        if (-Not $SyncHash.WPFControl_tbDeviceName.IsEnabled) { $SyncHash.WPFControl_tbDeviceName.IsEnabled = $true }
    }
)

$SyncHash.WPFControl_btnClear.Add_Click( 
    { # btnClear Click Action
        Update-Gui
        Reset-GUIForm
    }
)

$SyncHash.WPFControl_btnDeleteOtp.Add_Click( 
    { # btnDeleteOtp Click Action
        Update-Gui
        $SelectedItem = $SyncHash.WPFControl_lvOtps.SelectedItem
        $SyncHash.DeviceSecrets = @($SyncHash.DeviceSecrets | Where-Object { $_.Secret -ne $SelectedItem.Secret })
        $SyncHash.WPFControl_lvOtps.ItemsSource = $SyncHash.DeviceSecrets
        if (-Not $SyncHash.WPFControl_btnSaveOtp.IsEnabled) { $SyncHash.WPFControl_btnSaveOtp.IsEnabled = $true }
        if (-Not $SyncHash.WPFControl_btnExportPosh.IsEnabled) { $SyncHash.WPFControl_btnExportPosh.IsEnabled = $true }
        $SyncHash.Saved = $false
    }
)

$SyncHash.WPFControl_btnSaveOtp.Add_Click( 
    { # btnSaveOtp Click Action
        Update-Gui
        Save-OtpToUser
        Invoke-CleanGUIUser
    }
)

$SyncHash.WPFControl_btnExportPosh.Add_Click( 
    { # btnExportPosh Click Action
        Update-Gui
        Save-OtpToUserExportCommand
        if ($SyncHash.Saved) {
            Invoke-CleanGUIUser
        }
    }
)

$SyncHash.WPFControl_btnLoadOtp.Add_Click( 
    { # btnSaveOtp Click Action
        Invoke-CleanGUIQRImage
        $SelectedItem = $SyncHash.WPFControl_lvOtps.SelectedItem
        $SyncHash.WPFControl_tbSecret.Text = $SelectedItem.Secret
        $SyncHash.B32Secret = $SelectedItem.Secret
        $SyncHash.WPFControl_tbDeviceName.Text = $SelectedItem.DeviceName
    }
)

$SyncHash.WPFControl_btnAddQR.Add_Click( 
    { # btnAddQR Click Action
        Update-Gui
        if ($SyncHash.DeviceSecrets.Count -ge 4) {
            $null = [System.Windows.MessageBox]::Show("The maximum of allowed devices reached.`nTo continue remove one device!", "Maximum Reached!", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        } elseif ($SyncHash.DeviceSecrets | Where-Object DeviceName -eq $($SyncHash.WPFControl_tbDeviceName.Text)) {
            $null = [System.Windows.MessageBox]::Show("The Device Name `"$($SyncHash.WPFControl_tbDeviceName.Text)`" already exists", "Double Entry!", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        } elseif ($SyncHash.DeviceSecrets | Where-Object Secret -eq $($SyncHash.B32Secret)) {
            $null = [System.Windows.MessageBox]::Show("The Secret already exists!`nGenerate a new secret", "Double Entry!", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        } else {
            if (-Not $SyncHash.WPFControl_btnSaveOtp.IsEnabled) { $SyncHash.WPFControl_btnSaveOtp.IsEnabled = $true }
            if (-Not $SyncHash.WPFControl_btnExportPosh.IsEnabled) { $SyncHash.WPFControl_btnExportPosh.IsEnabled = $true }
            $SyncHash.DeviceSecrets += [PSCustomObject]@{
                DeviceName = $($SyncHash.WPFControl_tbDeviceName.Text)
                Secret     = $($SyncHash.B32Secret)
            }
            $SyncHash.WPFControl_lvOtps.ItemsSource = $SyncHash.DeviceSecrets
        }
        $SyncHash.Saved = $false
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
        Write-Verbose "Enter"
        Update-Gui
        Invoke-SearchADUser
    }
}


$SyncHash.WPFControl_tbAttribute.add_TextChanged( 
    { 
        Write-Verbose "tbAttribute Text Changed"
        $SyncHash.Attribute = $SyncHash.WPFControl_tbAttribute.Text
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
        Update-Gui
        Invoke-SearchADUser
    }
)

$SyncHash.WPFControl_lvUsernames.add_SelectionChanged( { 
        Write-Verbose "lvUsernames Selection Changed"
        Update-Gui
        Invoke-CleanGUIQR
        $SelectedItem = $SyncHash.WPFControl_lvUsernames.SelectedItem
        if (-Not [String]::IsNullOrEmpty($($SelectedItem.Attribute))) {
            $SyncHash.DeviceSecrets = @()
            $SyncHash.DeviceSecrets += ConvertFrom-Attribute -Data $SelectedItem.Attribute
            $SyncHash.WPFControl_lvOtps.ItemsSource = $SyncHash.DeviceSecrets
            if (-Not $SyncHash.WPFControl_tbDeviceName.IsEnabled) { $SyncHash.WPFControl_tbDeviceName.IsEnabled = $true }
            if (-Not $SyncHash.WPFControl_btnLoadOtp.IsEnabled) { $SyncHash.WPFControl_btnLoadOtp.IsEnabled = $true }
        } else {
            $SyncHash.WPFControl_lvOtps.ItemsSource = $null
            if ($SyncHash.WPFControl_tbDeviceName.IsEnabled) { $SyncHash.WPFControl_tbDeviceName.IsEnabled = $false }
            if ($SyncHash.WPFControl_btnLoadOtp.IsEnabled) { $SyncHash.WPFControl_btnLoadOtp.IsEnabled = $false }
        }
        
        
    }
)

$SyncHash.WPFControl_lvOtps.add_SelectionChanged( { 
        Write-Verbose "lvOtps Selection Changed" 
        Invoke-CleanTOTPToken
        Update-Gui
        $SelectedItem = $SyncHash.WPFControl_lvOtps.SelectedItem
        Write-Verbose "Selected item: $SelectedItem"
        $SyncHash.B32Secret = $SelectedItem.Secret
        if ([String]::IsNullOrEmpty($($SelectedItem.Secret))) {
            if ($SyncHash.WPFControl_btnDeleteOtp.IsEnabled) { $SyncHash.WPFControl_btnDeleteOtp.IsEnabled = $false }
        } else {
            if (-Not $SyncHash.WPFControl_btnDeleteOtp.IsEnabled) { $SyncHash.WPFControl_btnDeleteOtp.IsEnabled = $true }
            if (-Not $SyncHash.WPFControl_gbToken.IsEnabled) { $SyncHash.WPFControl_gbToken.IsEnabled = $true }
        }
    }
)

$SyncHash.WPFControl_btnGenerateQR.Add_Click( { # btnGenerateQR Click Action
        Update-Gui
        Invoke-CleanGUIQRImage
        if ($QRGeneration) {
            Get-GUIQRImage
            Update-Gui
            $SelectedItem = $SyncHash.WPFControl_lvUsernames.SelectedItem
            $SamAccountName = $SelectedItem.SamAccountName
            $DeviceName = $SyncHash.WPFControl_tbDeviceName.Text
            $Target = $SyncHash.WPFControl_tbGateway.Text
            $NetBIOSName = $SelectedItem.NetBIOSName
            
            $OTPUri = "otpauth://totp/"
            #Previous
            #$OTPUri += [Uri]::EscapeDataString($("{0}@{1}@{2}" -f $NetBIOSName,$SamAccountName,$Target))
            #Current 13.0 generation
            $OTPUri += [Uri]::EscapeDataString($("{0}@{1}" -f $SamAccountName, $Target))
            $OTPUri += "?secret={0}&device={1}" -f $SyncHash.B32Secret, $DeviceName
            Write-Verbose "OTP Uri: $OTPUri"
            $Script:QRImage = New-QRCodeURI -URI $OTPUri -OutStream
            #$ImgSource = New-Object System.Drawing.Bitmap($QRImage)
            #$Hbitmap = $ImgSource.GetHbitmap()
            #[System.Windows.Media.ImageSource]$QRImageSource = [System.Windows.Interop.Imaging]::CreateBitmapSourceFromHBitmap($Hbitmap, [System.IntPtr]::Zero, [System.Windows.Int32Rect]::Empty, [System.Windows.Media.Imaging.BitmapSizeOptions]::FromEmptyOptions());
            
            $QRImageSource = New-Object System.Windows.Media.Imaging.BitmapImage
            $QRImageSource.BeginInit()
            $QRImageSource.StreamSource = $Script:QRImage
            $QRImageSource.EndInit() 
            #$QRImageSource.Freeze()
            $SyncHash.WPFControl_ImgQR.Source = $QRImageSource
            $SyncHash.Saved = $false
            Show-QR
        } else {
            $null = [System.Windows.MessageBox]::Show("The PowerShell Module `"QRCodeGenerator`" was NOT Found!`nQR Code generation is disabled.", "QRCodeGenerator Module", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Exclamation)
        }
    }
)

$SyncHash.WPFControl_btnExportQR.Add_Click( {
        # btnExportQR Click Action
        try {
            $SelectedItem = $SyncHash.WPFControl_lvUsernames.SelectedItem
            $PNGPath = Save-File -FileName $("{0}_{1}_{2}.png" -f $SelectedItem.SamAccountName, $SyncHash.WPFControl_tbDeviceName.text, $SyncHash.WPFControl_tbGateway.text)
            Write-Verbose "PNGPath: $PNGPath"
            if (Test-Path (Split-Path -Path $PNGPath -Parent | Resolve-Path).Path) {
                [System.IO.File]::WriteAllBytes($PNGPath, $($Script:QRImage.ToArray()))
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

$SyncHash.WPFControl_btnViewTOTPToken.Add_Click( {
        # btnViewTOTPToken Click Action
        Write-Verbose "btnViewTOTPToken Click"
        try {
            $SyncHash.OTPToken = Get-OTPToken -B32Secret $SyncHash.B32Secret -TimeWindow $SyncHash.OTPTimeWindow -OTPLength $SyncHash.OTPLength
            $SyncHash.WPFControl_tbTOTPToken.Text = $SyncHash.OTPToken.OTP
            $SyncHash.OTPUpdate = $true
            $handle = $PoSH.BeginInvoke()
            Write-Verbose  $SyncHash.OTPToken
        } catch {
            Write-Verbose "$($_.Exception.Message)"
        }
    }
)

#endregion Event handlers

# Show/Run the App
$SyncHash.App.Run($SyncHash.Form)
try { $PoSH.EndInvoke($handle) } catch { }
$RunSpace.Close()
$PoSH.Dispose()