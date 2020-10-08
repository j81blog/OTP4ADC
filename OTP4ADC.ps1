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
    Version   : v0.1.2
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

function Generate-OTPSecret {
    [cmdletbinding()]
    param(
        [Int]$Length = 26
    )
    Write-Verbose "Function: Generate-OTPSecret"
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

function New-AuthenticatorSecret {
    [CmdletBinding()]
    Param(
        # Secret length in bytes, must be a multiple of 5 bits for neat BASE32 encoding
        [int]
        [ValidateScript( { ($_ * 8) % 5 -eq 0 })]
        $SecretLength = 15
    )
    Write-Verbose "Function: New-AuthenticatorSecret"


    $Base32Charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

    # Generate random bytes for the secret
    $byteArrayForSecret = [byte[]]::new($SecretLength)
    [Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes($byteArrayForSecret, 0, $SecretLength)
    

    # BASE32 encode the bytes
    # 5 bits per character doesn't align with 8-bits per byte input,
    # and needs careful code to take some bits from separate bytes.
    # Because we're in a scripting language let's dodge that work.
    # Instead, convert the bytes to a 10100011 style string:
    $byteArrayAsBinaryString = -join $byteArrayForSecret.ForEach{
        [Convert]::ToString($_, 2).PadLeft(8, '0')
    }


    # then use regex to get groups of 5 bits 
    # -> conver those to integer 
    # -> lookup that as an index into the BASE32 character set 
    # -> result string
    $Base32Secret = [regex]::Replace($byteArrayAsBinaryString, '.{5}', {
            param($Match)
            $Base32Charset[[Convert]::ToInt32($Match.Value, 2)]
        })

    return $Base32Secret
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

function Extract-Attribute {
    [CmdLetBinding()]
    [OutputType('PSCustomObject')]
    param(
        [String]$Data
    )
    Write-Verbose "Function: Extract-Attribute"

    if ($Data.Length -gt 2) {
        $Result = $Data.Substring(2).Split(',') | ForEach { [PSCustomObject]@{
                DeviceName = $($_.Split('=')[0])
                Secret     = $(($_.Replace('&', '').Split('=')[1]))
            } } | Where-Object { $_.Secret } | Sort-Object DeviceName
    }
    return $Result | Sort-Object DeviceName
}

function Initialize-GUI {
    Write-Verbose "Function: Initialize-GUI"
    $Form.WindowStartupLocation = [System.Windows.WindowStartupLocation]::CenterScreen
    $WPFControl_tbAttribute.Text = $Attribute
    $Script:OTPDevices = [PSCustomObject]@()
    $Script:DeviceSecrets = [PSCustomObject]@()
    Reset-GUIForm
}

function Update-Gui {
    #Fixes the "freeze" problem
    Write-Verbose "Function: Update-Gui"
    # Basically WinForms Application.DoEvents()
    try { $App.Dispatcher.Invoke([Windows.Threading.DispatcherPriority]::Background, [action] { }) } catch { }
}

function Clean-GUIQRImage {
    Write-Verbose "Function: Clean-GUIQRImage"
    if ($WPFControl_btnGenerateQR.IsEnabled) { $WPFControl_btnGenerateQR.IsEnabled = $false }
    if ($WPFControl_btnExportQR.IsEnabled) { $WPFControl_btnExportQR.IsEnabled = $false }
    $WPFControl_ImgQR.Source = $null
    #$WPFControl_ImgQR.Visibility = [System.Windows.Visibility]::Hidden
    if ($QRGeneration) { $WPFControl_lblQR.Content = "" }
    $Script:QRImage = $null
    Validate-GenerateQR
    Validate-AddSecret
}

function Load-QR {
    Write-Verbose "Function: Load-QR"
    Clean-GUIQRImage
    $WPFControl_lblQR.Content = "Loading QR..."

}

function Show-QR {
    Write-Verbose "Function: Show-QR"
    #$WPFControl_ImgQR.Visibility = [System.Windows.Visibility]::Visible
    $WPFControl_lblQR.Content = ""
    if (-Not $WPFControl_btnExportQR.IsEnabled) { $WPFControl_btnExportQR.IsEnabled = $true }
    $WPFControl_btnExportQR.Focus() | Out-Null
}

function Search-User {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Name,
        
        [String]$Attribute = $Script:Attribute
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
        $MBResult = [System.Windows.MessageBox]::Show("$($_.Exception.Message)", "Error!", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
    return $Results 
}

function Clean-GUIUser {
    Write-Verbose "Function: Clean-GUIUser"
    if ($Script:Saved) {
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
        $WPFControl_lvUsernames.ItemsSource = $null
        $WPFControl_tbUsername.Text = ""
        $WPFControl_lvOtps.ItemsSource = $null
        if ($WPFControl_btnDeleteOtp.IsEnabled) { $WPFControl_btnDeleteOtp.IsEnabled = $false }
        if ($WPFControl_btnLoadOtp.IsEnabled) { $WPFControl_btnLoadOtp.IsEnabled = $false }
        if ($WPFControl_btnSaveOtp.IsEnabled) { $WPFControl_btnSaveOtp.IsEnabled = $false }
        $Script:Saved = $true
        Clean-GUIQR
    }
}

function Clean-GUIQR {
    Write-Verbose "Function: Clean-GUIQR"
    $WPFControl_tbSecret.Text = ""
    $WPFControl_tbDeviceName.Text = ""
    $WPFControl_tbGateway.Text = $GatewayURI
    if ($WPFControl_btnAddQR.IsEnabled) { $WPFControl_btnAddQR.IsEnabled = $false }
    Clean-GUIQRImage
}

function Reset-GUIForm {
    [CmdLetBinding()]
    param()
    Write-Verbose "Function: Reset-GUIForm"
    Clean-GUIUser
    $WPFControl_tbUsername.Focus() | Out-Null
}

function Save-OtpToUser {
    Write-Verbose "Function: Save-OtpToUser"
    $SelectedUser = $WPFControl_lvUsernames.SelectedItem
    $DistinguishedName = $SelectedUser.DistinguishedName
    $User = Get-ADUser -Identity $DistinguishedName
    if ($Script:DeviceSecrets.Count -gt 0) {
        $NewOTP = @()
        ForEach ($Item in $Script:DeviceSecrets) {
            $NewOTP += "{0}={1}" -f $Item.DeviceName, $Item.Secret
        }
        $NewOTPString = "#@$($NewOTP -Join '&,')&,"
        Write-Verbose "New OTP AD User String: `"$NewOTPString`""
        #$DeviceName = $WPFControl_tbDeviceName.text
        $User | Set-ADUser -Replace @{ "$Attribute" = $NewOTPString }
    } else {
        Write-Verbose "No OTP for user, save empty string"
        $NewOTPString = $null
        $User | Set-ADUser -Clear @("$Attribute")
    }
    $Script:Saved = $true
}

function Validate-GenerateQR {
    Write-Verbose "Function: Validate-GenerateQR"
    Update-Gui
    if (([String]::IsNullOrEmpty($($WPFControl_tbGateway.Text))) -or ([String]::IsNullOrEmpty($($WPFControl_tbDeviceName.Text))) -or ([String]::IsNullOrEmpty($($WPFControl_tbSecret.Text)))) {
        if ($WPFControl_btnGenerateQR.IsEnabled) { $WPFControl_btnGenerateQR.IsEnabled = $false }
    } else {
        if (-Not $WPFControl_btnGenerateQR.IsEnabled) { $WPFControl_btnGenerateQR.IsEnabled = $true }
    }
}

function Validate-AddSecret {
    Write-Verbose "Function: Validate-AddSecret"
    if (([String]::IsNullOrEmpty($($WPFControl_tbDeviceName.Text))) -or ([String]::IsNullOrEmpty($($WPFControl_tbSecret.Text)))) {
        if ($WPFControl_btnAddQR.IsEnabled) { $WPFControl_btnAddQR.IsEnabled = $false }
    } else {
        if (-Not $WPFControl_btnAddQR.IsEnabled) { $WPFControl_btnAddQR.IsEnabled = $true }
    }
}

function Execute-SearchADUser {
    Write-Verbose "Function: Execute-SearchADUser"
    if ([String]::IsNullOrEmpty($($WPFControl_tbUsername.Text))) {
        $result = [System.Windows.MessageBox]::Show("The Username field is empty!", "Username Empty", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    } else {
        $Results = Search-User -Name $WPFControl_tbUsername.Text
        $WPFControl_lvUsernames.ItemsSource = @($Results)
    }
}

function Start-App {
    if (-Not $Script:AppStarted) {
        Write-Verbose "Function: Start-App"
        try {
            Load-Modules
            Load-AppImage
            Initialize-GUI
            $Script:AppStarted = $true
        } catch { "ERROR: $($_.Exception.Message)" }
    }
}

function Load-Modules {

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
        $WPFControl_tbUsername.Text = "ActiveDirectory Module NOT Found!"
        if ($WPFControl_gbUser.IsEnabled) { $WPFControl_gbUser.IsEnabled = $false }
        $result = [System.Windows.MessageBox]::Show("The PowerShell Module `"ActiveDirectory`" was NOT Found!", "ActiveDirectory Module", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
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
                    #$WPFControl_lblQR.Content = "NOT AVAILABLE!"
                    $result = [System.Windows.MessageBox]::Show("Nuget PackageProvider was NOT Found!`nThis is required to install QRCodeGenerator`nInstall manually or Re-Run As Administrator", "NuGet Not Available", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Exclamation)
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
        #$WPFControl_lblQR.Content = "NOT AVAILABLE!"
        $result = [System.Windows.MessageBox]::Show("The PowerShell Module `"QRCodeGenerator`" was NOT Found!`nQR Code generation is disabled.", "QRCodeGenerator Module", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Exclamation)
    }
}

function Load-AppImage {
    $AppImage = New-Object System.Windows.Media.Imaging.BitmapImage
    $AppImage.BeginInit()
    $AppImage.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($AppImageB64)
    $AppImage.EndInit()
    $AppImage.Freeze()
    $Form.Icon = $AppImage
    $WPFControl_AppImage.Source = $AppImage
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
Clear-Host

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


#[System.Convert]::ToBase64String([system.Text.Encoding]::UTF8.GetBytes($(Get-Content -Path "C:\Users\John.Billekens\stack\Visual Studio\Repo\OTP4ADC\OTP4ADC\OTP4ADC\MainWindow.xaml" -Raw))) | clip.exe
$XAMLDataB64 = @"
PFdpbmRvdyB4OkNsYXNzPSJPVFA0QURDLk1haW5XaW5kb3ciDQogICAgICAgIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbC9wcmVzZW50YXRpb24iDQogICAgICAgIHhtbG5zOng9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sIg0KICAgICAgICB4bWxuczpkPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2V4cHJlc3Npb24vYmxlbmQvMjAwOCINCiAgICAgICAgeG1sbnM6bWM9Imh0dHA6Ly9zY2hlbWFzLm9wZW54bWxmb3JtYXRzLm9yZy9tYXJrdXAtY29tcGF0aWJpbGl0eS8yMDA2Ig0KICAgICAgICB4bWxuczpsb2NhbD0iY2xyLW5hbWVzcGFjZTpPVFA0QURDIg0KICAgICAgICBtYzpJZ25vcmFibGU9ImQiIA0KICAgICAgICBUaXRsZT0iT1RQNEFEQyIgU2l6ZVRvQ29udGVudD0iV2lkdGhBbmRIZWlnaHQiIFJlc2l6ZU1vZGU9Ik5vUmVzaXplIiBIZWlnaHQ9IkF1dG8iIFdpZHRoPSJBdXRvIj4NCiAgICA8R3JpZCBNYXJnaW49IjIiPg0KICAgICAgICA8R3JpZC5Sb3dEZWZpbml0aW9ucz4NCiAgICAgICAgICAgIDxSb3dEZWZpbml0aW9uIEhlaWdodD0iQXV0byIvPg0KICAgICAgICAgICAgPFJvd0RlZmluaXRpb24gSGVpZ2h0PSJBdXRvIi8+DQogICAgICAgICAgICA8Um93RGVmaW5pdGlvbiBIZWlnaHQ9IkF1dG8iLz4NCiAgICAgICAgPC9HcmlkLlJvd0RlZmluaXRpb25zPg0KICAgICAgICA8R3JpZC5Db2x1bW5EZWZpbml0aW9ucz4NCiAgICAgICAgICAgIDxDb2x1bW5EZWZpbml0aW9uIFdpZHRoPSJBdXRvIi8+DQogICAgICAgICAgICA8Q29sdW1uRGVmaW5pdGlvbiBXaWR0aD0iQXV0byIvPg0KICAgICAgICAgICAgPENvbHVtbkRlZmluaXRpb24gV2lkdGg9IkF1dG8iLz4NCiAgICAgICAgPC9HcmlkLkNvbHVtbkRlZmluaXRpb25zPg0KICAgICAgICA8R3JvdXBCb3ggTmFtZT0iZ2JVc2VyIiBHcmlkLlJvdz0iMCIgR3JpZC5Db2x1bW49IjAiIEhlYWRlcj0iVXNlciIgSGVpZ2h0PSJBdXRvIiBNYXJnaW49IjIiIFdpZHRoPSJBdXRvIj4NCiAgICAgICAgICAgIDxHcmlkIE1hcmdpbj0iNSI+DQogICAgICAgICAgICAgICAgPEdyaWQuUm93RGVmaW5pdGlvbnM+DQogICAgICAgICAgICAgICAgICAgIDxSb3dEZWZpbml0aW9uIEhlaWdodD0iQXV0byIvPg0KICAgICAgICAgICAgICAgICAgICA8Um93RGVmaW5pdGlvbiBIZWlnaHQ9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICAgICAgPFJvd0RlZmluaXRpb24gSGVpZ2h0PSJBdXRvIi8+DQogICAgICAgICAgICAgICAgICAgIDxSb3dEZWZpbml0aW9uIEhlaWdodD0iQXV0byIvPg0KICAgICAgICAgICAgICAgICAgICA8Um93RGVmaW5pdGlvbiBIZWlnaHQ9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICAgICAgPFJvd0RlZmluaXRpb24gSGVpZ2h0PSJBdXRvIi8+DQogICAgICAgICAgICAgICAgICAgIDxSb3dEZWZpbml0aW9uIEhlaWdodD0iQXV0byIvPg0KICAgICAgICAgICAgICAgIDwvR3JpZC5Sb3dEZWZpbml0aW9ucz4NCiAgICAgICAgICAgICAgICA8R3JpZC5Db2x1bW5EZWZpbml0aW9ucz4NCiAgICAgICAgICAgICAgICAgICAgPENvbHVtbkRlZmluaXRpb24gV2lkdGg9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICAgICAgPENvbHVtbkRlZmluaXRpb24gV2lkdGg9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICAgICAgPENvbHVtbkRlZmluaXRpb24gV2lkdGg9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICA8L0dyaWQuQ29sdW1uRGVmaW5pdGlvbnM+DQogICAgICAgICAgICAgICAgPExhYmVsIE5hbWU9ImxibFVzZXJuYW1lIiBHcmlkLlJvdz0iMCIgR3JpZC5Db2x1bW49IjAiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBXaWR0aD0iODAiIE1hcmdpbj0iMiIgQ29udGVudD0iVXNlcm5hbWUiIC8+DQogICAgICAgICAgICAgICAgPFRleHRCb3ggTmFtZT0idGJVc2VybmFtZSIgR3JpZC5Sb3c9IjAiIEdyaWQuQ29sdW1uPSIxIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgTWFyZ2luPSIyIiBUZXh0PSIiIFdpZHRoPSIyNTAiIFRvb2xUaXA9IkVudGVyIHRoZSBVc2VybmFtZSBvciBwYXJ0IG9mIHRoZSB1c2VybmFtZSIgVGFiSW5kZXg9IjEwIiAvPg0KICAgICAgICAgICAgICAgIDxCdXR0b24gTmFtZT0iYnRuU2VhcmNoIiBHcmlkLlJvdz0iMCIgR3JpZC5Db2x1bW49IjIiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBNYXJnaW49IjIiIENvbnRlbnQ9IlNlYXJjaCIgV2lkdGg9IjEwMCIgSGVpZ2h0PSJBdXRvIiBUYWJJbmRleD0iMjAiIC8+DQogICAgICAgICAgICAgICAgPExpc3RWaWV3IE5hbWU9Imx2VXNlcm5hbWVzIiBHcmlkLlJvdz0iMSIgR3JpZC5Db2x1bW49IjEiIEdyaWQuUm93U3Bhbj0iMiIgVmVydGljYWxDb250ZW50QWxpZ25tZW50PSJUb3AiIE1hcmdpbj0iMiIgSGVpZ2h0PSI4MCIgV2lkdGg9IjI1MCIgRm9udFNpemU9IjgiIFNlbGVjdGlvbk1vZGU9IlNpbmdsZSIgVGFiSW5kZXg9IjMwIiA+DQogICAgICAgICAgICAgICAgICAgIDxMaXN0Vmlldy5WaWV3Pg0KICAgICAgICAgICAgICAgICAgICAgICAgPEdyaWRWaWV3Pg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxHcmlkVmlld0NvbHVtbiBIZWFkZXI9IlNhbUFjY291bnROYW1lIiBEaXNwbGF5TWVtYmVyQmluZGluZz0ie0JpbmRpbmcgU2FtQWNjb3VudE5hbWV9IiAvPg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxHcmlkVmlld0NvbHVtbiBIZWFkZXI9IlVQTiIgRGlzcGxheU1lbWJlckJpbmRpbmc9IntCaW5kaW5nIFVzZXJQcmluY2lwYWxOYW1lfSIgLz4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8R3JpZFZpZXdDb2x1bW4gSGVhZGVyPSJHaXZlbk5hbWUiIERpc3BsYXlNZW1iZXJCaW5kaW5nPSJ7QmluZGluZyBHaXZlbk5hbWV9IiAvPg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxHcmlkVmlld0NvbHVtbiBIZWFkZXI9IlN1cm5hbWUiIERpc3BsYXlNZW1iZXJCaW5kaW5nPSJ7QmluZGluZyBTdXJuYW1lfSIgLz4NCiAgICAgICAgICAgICAgICAgICAgICAgIDwvR3JpZFZpZXc+DQogICAgICAgICAgICAgICAgICAgIDwvTGlzdFZpZXcuVmlldz4NCg0KICAgICAgICAgICAgICAgIDwvTGlzdFZpZXc+DQoNCiAgICAgICAgICAgICAgICA8QnV0dG9uIE5hbWU9ImJ0bkNsZWFyIiBHcmlkLlJvdz0iMSIgR3JpZC5Db2x1bW49IjIiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBNYXJnaW49IjIiIENvbnRlbnQ9IkNsZWFyIiBXaWR0aD0iMTAwIiBWZXJ0aWNhbEFsaWdubWVudD0iVG9wIiBIZWlnaHQ9IjI3IiAgLz4NCg0KICAgICAgICAgICAgICAgIDxMYWJlbCBOYW1lPSJsYmxBdHRyaWJ1dGUiIEdyaWQuUm93PSIzIiBHcmlkLkNvbHVtbj0iMCIgVmVydGljYWxDb250ZW50QWxpZ25tZW50PSJUb3AiIE1hcmdpbj0iMiIgQ29udGVudD0iQXR0cmlidXRlIiBXaWR0aD0iOTAiIC8+DQogICAgICAgICAgICAgICAgPFRleHRCb3ggTmFtZT0idGJBdHRyaWJ1dGUiIEdyaWQuUm93PSIzIiBHcmlkLkNvbHVtbj0iMSIgVmVydGljYWxDb250ZW50QWxpZ25tZW50PSJDZW50ZXIiIE1hcmdpbj0iMiIgVGV4dD0iIiBXaWR0aD0iMjUwIiBUb29sVGlwPSJDYW4gYmUgcHJlLWNvbmZpZ3VyZWQgYnkgc3RhcnRpbmcgdGhlIGFwcGxpY2F0aW9uIHdpdGggdGhlIC1BdHRyaWJ1dGUgJyZsdDtBRCBBdHRyaWJ1dGUmZ3Q7JyBwYXJhbWV0ZXIsIGlmIG5vdCBjb25maWd1cmVkIGl0IHVzZXMgdGhlIGRlZmF1bHQgJ3VzZXJQYXJhbWV0ZXJzJyIgLz4NCiAgICAgICAgICAgICAgICA8TGFiZWwgTmFtZT0ibGJsT3RwIiBHcmlkLlJvdz0iNCIgR3JpZC5Db2x1bW49IjAiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iVG9wIiBNYXJnaW49IjIiIENvbnRlbnQ9Ik9UUCIgV2lkdGg9IjkwIiAgVmVydGljYWxBbGlnbm1lbnQ9IlRvcCIvPg0KICAgICAgICAgICAgICAgIDxMaXN0VmlldyBOYW1lPSJsdk90cHMiIEdyaWQuUm93PSI0IiBHcmlkLkNvbHVtbj0iMSIgR3JpZC5Sb3dTcGFuPSIzIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IlRvcCIgTWFyZ2luPSIyIiAgV2lkdGg9IjI1MCIgRm9udFNpemU9IjgiIFNlbGVjdGlvbk1vZGU9IlNpbmdsZSIgSGVpZ2h0PSIxMjAiIFRhYkluZGV4PSI0MCIgID4NCiAgICAgICAgICAgICAgICAgICAgPExpc3RWaWV3LlZpZXc+DQogICAgICAgICAgICAgICAgICAgICAgICA8R3JpZFZpZXc+DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgPEdyaWRWaWV3Q29sdW1uIEhlYWRlcj0iRGV2aWNlIE5hbWUiIFdpZHRoPSJBdXRvIiBEaXNwbGF5TWVtYmVyQmluZGluZz0ie0JpbmRpbmcgRGV2aWNlTmFtZX0iIC8+DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgPEdyaWRWaWV3Q29sdW1uIEhlYWRlcj0iU2VjcmV0IiBXaWR0aD0iQXV0byIgRGlzcGxheU1lbWJlckJpbmRpbmc9IntCaW5kaW5nIFNlY3JldH0iIC8+DQogICAgICAgICAgICAgICAgICAgICAgICAgPC9HcmlkVmlldz4NCiAgICAgICAgICAgICAgICAgICAgPC9MaXN0Vmlldy5WaWV3Pg0KICAgICAgICAgICAgICAgIDwvTGlzdFZpZXc+DQogICAgICAgICAgICAgICAgPFN0YWNrUGFuZWwgR3JpZC5Sb3c9IjQiIEdyaWQuQ29sdW1uPSIyIiBHcmlkLlJvd1NwYW49IjMiIEhvcml6b250YWxBbGlnbm1lbnQ9IlN0cmV0Y2giIFZlcnRpY2FsQWxpZ25tZW50PSJTdHJldGNoIiA+DQogICAgICAgICAgICAgICAgICAgIDxCdXR0b24gTmFtZT0iYnRuRGVsZXRlT3RwIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgTWFyZ2luPSIyIiBDb250ZW50PSJEZWxldGUiIFdpZHRoPSIxMDAiIFZlcnRpY2FsQWxpZ25tZW50PSJUb3AiIEhlaWdodD0iMjciIC8+DQogICAgICAgICAgICAgICAgICAgIDxCdXR0b24gTmFtZT0iYnRuU2F2ZU90cCIgVmVydGljYWxDb250ZW50QWxpZ25tZW50PSJDZW50ZXIiIE1hcmdpbj0iMiIgQ29udGVudD0iU2F2ZSIgV2lkdGg9IjEwMCIgVmVydGljYWxBbGlnbm1lbnQ9IlRvcCIgSGVpZ2h0PSIyNyIgLz4NCiAgICAgICAgICAgICAgICAgICAgPEJ1dHRvbiBOYW1lPSJidG5Mb2FkT3RwIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgTWFyZ2luPSIyIiBDb250ZW50PSJMb2FkIiBXaWR0aD0iMTAwIiBWZXJ0aWNhbEFsaWdubWVudD0iVG9wIiBIZWlnaHQ9IjI3IiBUYWJJbmRleD0iNTAiIC8+DQogICAgICAgICAgICAgICAgPC9TdGFja1BhbmVsPg0KICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgPC9HcmlkPg0KICAgICAgICA8L0dyb3VwQm94Pg0KICAgICAgICA8R3JvdXBCb3ggR3JpZC5Sb3c9IjAiIEdyaWQuQ29sdW1uPSIxIiBIZWFkZXI9IlFSIiBIZWlnaHQ9IkF1dG8iIE1hcmdpbj0iMiIgV2lkdGg9IkF1dG8iPg0KICAgICAgICAgICAgPEdyaWQgTWFyZ2luPSI1Ij4NCiAgICAgICAgICAgICAgICA8R3JpZC5Sb3dEZWZpbml0aW9ucz4NCiAgICAgICAgICAgICAgICAgICAgPFJvd0RlZmluaXRpb24gSGVpZ2h0PSJBdXRvIi8+DQogICAgICAgICAgICAgICAgICAgIDxSb3dEZWZpbml0aW9uIEhlaWdodD0iQXV0byIvPg0KICAgICAgICAgICAgICAgICAgICA8Um93RGVmaW5pdGlvbiBIZWlnaHQ9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICA8L0dyaWQuUm93RGVmaW5pdGlvbnM+DQogICAgICAgICAgICAgICAgPEdyaWQuQ29sdW1uRGVmaW5pdGlvbnM+DQogICAgICAgICAgICAgICAgICAgIDxDb2x1bW5EZWZpbml0aW9uIFdpZHRoPSJBdXRvIi8+DQogICAgICAgICAgICAgICAgPC9HcmlkLkNvbHVtbkRlZmluaXRpb25zPg0KICAgICAgICAgICAgICAgIDxJbWFnZSBOYW1lPSJJbWdRUiIgR3JpZC5Sb3c9IjAiIEdyaWQuQ29sdW1uPSIwIiBNYXJnaW49IjIiIEhlaWdodD0iMjAwIiBXaWR0aD0iMjAwIiBWaXNpYmlsaXR5PSJWaXNpYmxlIiBTdHJldGNoPSJVbmlmb3JtVG9GaWxsIiBSZW5kZXJUcmFuc2Zvcm1PcmlnaW49IjAuNSwwLjUiIC8+DQogICAgICAgICAgICAgICAgPExhYmVsIE5hbWU9ImxibFFSIiBHcmlkLlJvdz0iMSIgR3JpZC5Db2x1bW49IjAiIE1hcmdpbj0iMiIgQ29udGVudD0iIiBWZXJ0aWNhbEFsaWdubWVudD0iQm90dG9tIiBIb3Jpem9udGFsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgVmlzaWJpbGl0eT0iVmlzaWJsZSIgRm9udFdlaWdodD0iQm9sZCIgRm9udFNpemU9IjE2Ii8+DQogICAgICAgICAgICAgICAgPEJ1dHRvbiBOYW1lPSJidG5FeHBvcnRRUiIgR3JpZC5Sb3c9IjIiIEdyaWQuQ29sdW1uPSIwIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgTWFyZ2luPSIyIiBDb250ZW50PSJFeHBvcnQgUVIiIFdpZHRoPSIxMDAiIFZlcnRpY2FsQWxpZ25tZW50PSJCb3R0b20iIEhlaWdodD0iMjciIFRhYkluZGV4PSIxMDAiIC8+DQogICAgICAgICAgICA8L0dyaWQ+DQogICAgICAgIDwvR3JvdXBCb3g+DQogICAgICAgIDxHcm91cEJveCBHcmlkLlJvdz0iMSIgR3JpZC5Db2x1bW49IjAiIEhlYWRlcj0iVE9UUCIgSGVpZ2h0PSJhdXRvIiBNYXJnaW49IjIiIFdpZHRoPSJBdXRvIj4NCiAgICAgICAgICAgIDxHcmlkIE1hcmdpbj0iNSI+DQogICAgICAgICAgICAgICAgPEdyaWQuUm93RGVmaW5pdGlvbnM+DQogICAgICAgICAgICAgICAgICAgIDxSb3dEZWZpbml0aW9uIEhlaWdodD0iQXV0byIvPg0KICAgICAgICAgICAgICAgICAgICA8Um93RGVmaW5pdGlvbiBIZWlnaHQ9IkF1dG8iLz4NCiAgICAgICAgICAgICAgICAgICAgPFJvd0RlZmluaXRpb24gSGVpZ2h0PSJBdXRvIi8+DQogICAgICAgICAgICAgICAgPC9HcmlkLlJvd0RlZmluaXRpb25zPg0KICAgICAgICAgICAgICAgIDxHcmlkLkNvbHVtbkRlZmluaXRpb25zPg0KICAgICAgICAgICAgICAgICAgICA8Q29sdW1uRGVmaW5pdGlvbiBXaWR0aD0iQXV0byIvPg0KICAgICAgICAgICAgICAgICAgICA8Q29sdW1uRGVmaW5pdGlvbiBXaWR0aD0iQXV0byIvPg0KICAgICAgICAgICAgICAgICAgICA8Q29sdW1uRGVmaW5pdGlvbiBXaWR0aD0iQXV0byIvPg0KICAgICAgICAgICAgICAgIDwvR3JpZC5Db2x1bW5EZWZpbml0aW9ucz4NCiAgICAgICAgICAgICAgICA8TGFiZWwgTmFtZT0ibGJsU2VjcmV0IiBHcmlkLlJvdz0iMCIgR3JpZC5Db2x1bW49IjAiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBXaWR0aD0iOTAiIE1hcmdpbj0iMiIgQ29udGVudD0iU2VjcmV0IiAvPg0KICAgICAgICAgICAgICAgIDxUZXh0Qm94IE5hbWU9InRiU2VjcmV0IiBHcmlkLlJvdz0iMCIgR3JpZC5Db2x1bW49IjEiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBNYXJnaW49IjIiIFRleHQ9IiIgV2lkdGg9IjI1MCIgSXNSZWFkT25seT0iVHJ1ZSIgLz4NCiAgICAgICAgICAgICAgICA8QnV0dG9uIE5hbWU9ImJ0bkdlbmVyYXRlU2VjcmV0IiBHcmlkLlJvdz0iMCIgR3JpZC5Db2x1bW49IjIiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBNYXJnaW49IjIiIENvbnRlbnQ9IkdlbmVyYXRlIFNlY3JldCIgV2lkdGg9IjEwMCIgVGFiSW5kZXg9IjYwIiAvPg0KICAgICAgICAgICAgICAgIDxMYWJlbCBOYW1lPSJsYmxEZXZpY2VOYW1lIiBHcmlkLlJvdz0iMSIgR3JpZC5Db2x1bW49IjAiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBXaWR0aD0iOTAiIE1hcmdpbj0iMiIgQ29udGVudD0iRGV2aWNlIE5hbWUiIC8+DQogICAgICAgICAgICAgICAgPFRleHRCb3ggTmFtZT0idGJEZXZpY2VOYW1lIiBHcmlkLlJvdz0iMSIgR3JpZC5Db2x1bW49IjEiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBNYXJnaW49IjIiIFRleHQ9IiIgV2lkdGg9IjI1MCIgVGFiSW5kZXg9IjcwIiAvPg0KICAgICAgICAgICAgICAgIDxCdXR0b24gTmFtZT0iYnRuQWRkUVIiIEdyaWQuUm93PSIxIiBHcmlkLkNvbHVtbj0iMiIgVmVydGljYWxDb250ZW50QWxpZ25tZW50PSJDZW50ZXIiIE1hcmdpbj0iMiIgQ29udGVudD0iQWRkIiBXaWR0aD0iMTAwIiAvPg0KICAgICAgICAgICAgICAgIDxMYWJlbCBOYW1lPSJsYmxHYXRld2F5IiBHcmlkLlJvdz0iMiIgR3JpZC5Db2x1bW49IjAiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBXaWR0aD0iOTAiIE1hcmdpbj0iMiIgQ29udGVudD0iR2F0ZXdheSBmcWRuIiAvPg0KICAgICAgICAgICAgICAgIDxUZXh0Qm94IE5hbWU9InRiR2F0ZXdheSIgR3JpZC5Sb3c9IjIiIEdyaWQuQ29sdW1uPSIxIiBWZXJ0aWNhbENvbnRlbnRBbGlnbm1lbnQ9IkNlbnRlciIgTWFyZ2luPSIyIiBUZXh0PSIiIFdpZHRoPSIyNTAiIFRvb2xUaXA9IkNhbiBiZSBwcmUtY29uZmlndXJlZCBieSBzdGFydGluZyB0aGUgYXBwbGljYXRpb24gd2l0aCB0aGUgLUdhdGV3YXlVcmkgJyZsdDtndy5kb21haW4uY29tJmd0OycgcGFyYW1ldGVyIiBUYWJJbmRleD0iODAiIC8+DQogICAgICAgICAgICAgICAgPEJ1dHRvbiBOYW1lPSJidG5HZW5lcmF0ZVFSIiBHcmlkLlJvdz0iMiIgR3JpZC5Db2x1bW49IjIiIFZlcnRpY2FsQ29udGVudEFsaWdubWVudD0iQ2VudGVyIiBNYXJnaW49IjIiIENvbnRlbnQ9IkdlbmVyYXRlIFFSIiBXaWR0aD0iMTAwIiBWZXJ0aWNhbEFsaWdubWVudD0iVG9wIiBIZWlnaHQ9IjI3IiBUYWJJbmRleD0iOTAiIC8+DQogICAgICAgICAgICA8L0dyaWQ+DQogICAgICAgIDwvR3JvdXBCb3g+DQogICAgICAgIDxJbWFnZSBOYW1lPSJBcHBJbWFnZSIgIEdyaWQuQ29sdW1uPSIxIiAgR3JpZC5Sb3c9IjEiIEhvcml6b250YWxBbGlnbm1lbnQ9IlJpZ2h0IiBIZWlnaHQ9IjEwMCIgVmVydGljYWxBbGlnbm1lbnQ9IkJvdHRvbSIgV2lkdGg9IjEwMCIvPg0KICAgIDwvR3JpZD4NCjwvV2luZG93Pg0K
"@
# [Convert]::ToBase64String(($QRImage.ToArray())) | clip.exe
$AppImageB64 = @"
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
"@

$InputXML = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($XAMLDataB64))
[XML]$XAML = $InputXML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'

try {
    $App = [Windows.Application]::new()
    $Form = [Windows.Markup.XamlReader]::Load( [Xml.XmlNodeReader]::new($XAML) )
} catch {
    Write-Warning "Unable to parse XML, with error: $($Error[0])`n Ensure that there are NO SelectionChanged or TextChanged properties in your textboxes (PowerShell cannot process them)"
    throw
}

$XAML.SelectNodes("//*[@Name]") | ForEach-Object {
    try {
        Set-Variable -Name "WPFControl_$($_.Name)" -Value $Form.FindName($_.Name) -ErrorAction Stop
    } catch {
        throw
    }
}

Write-Verbose "Defining intractable elements"
$Controls = Get-Variable WPFControl_*

$Saved = $true

#region Event handlers

#System.ComponentModel.CancelEventHandler Closing(System.Object, System.ComponentModel.CancelEventArgs)
$Form.add_Closing( {
        Write-Verbose "GUI Closing"
        try {
            Clean-GUIQRImage
            $Form.Close()
            $App.Shutdown()
            if (-Not $NoHide) {
                Stop-Process -Id $PID 
            } elseif ($Console) {
                # return to console
                [Win32.Functions]::ShowWindow($hWnd, $SW_SHOW)
            }
        } catch { "ERROR: $($_.Exception.Message)" } 
    })


#System.EventHandler Initialized(System.Object, System.EventArgs)
#System.EventHandler Activated(System.Object, System.EventArgs)

$Form.add_Loaded(
    {
        Write-Verbose "GUI Loaded"
    })

$Form.add_Activated( {
        Write-Verbose "GUI Activated"
        Start-App
    })

#System.Windows.DependencyPropertyChangedEventHandler IsVisibleChanged(System.Object, System.Windows.DependencyPropertyChangedEventArgs)

$WPFControl_btnGenerateSecret.Add_Click( 
    { # btnGenerateSecret Click Action
        Update-Gui
        Clean-GUIQRImage
        $Script:B32Secret = Generate-OTPSecret
        #$Script:B32Secret = New-AuthenticatorSecret
        $WPFControl_tbSecret.Text = $Script:B32Secret
        if (-Not $WPFControl_tbDeviceName.IsEnabled) { $WPFControl_tbDeviceName.IsEnabled = $true }
    }
)

$WPFControl_btnClear.Add_Click( 
    { # btnClear Click Action
        Update-Gui
        Reset-GUIForm
    }
)

$WPFControl_btnDeleteOtp.Add_Click( 
    { # btnDeleteOtp Click Action
        Update-Gui
        $SelectedItem = $WPFControl_lvOtps.SelectedItem
        $Script:DeviceSecrets = @($Script:DeviceSecrets | Where-Object { $_.Secret -ne $SelectedItem.Secret })
        $WPFControl_lvOtps.ItemsSource = $Script:DeviceSecrets
        if (-Not $WPFControl_btnSaveOtp.IsEnabled) { $WPFControl_btnSaveOtp.IsEnabled = $true }
        $Script:Saved = $false
    }
)

$WPFControl_btnSaveOtp.Add_Click( 
    { # btnSaveOtp Click Action
        Update-Gui
        Save-OtpToUser
        Clean-GUIUser
    }
)

$WPFControl_btnLoadOtp.Add_Click( 
    { # btnSaveOtp Click Action
        Clean-GUIQRImage
        $SelectedItem = $WPFControl_lvOtps.SelectedItem
        $WPFControl_tbSecret.Text = $SelectedItem.Secret
        $Script:B32Secret = $SelectedItem.Secret
        $WPFControl_tbDeviceName.Text = $SelectedItem.DeviceName
    }
)

$WPFControl_btnAddQR.Add_Click( 
    { # btnAddQR Click Action
        Update-Gui
        if ($Script:DeviceSecrets.Count -ge 4) {
            $result = [System.Windows.MessageBox]::Show("The maximum of allowed devices reached.`nTo continue remove one device!", "Maximum Reached!", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        } elseif ($Script:DeviceSecrets | Where DeviceName -eq $($WPFControl_tbDeviceName.Text)) {
            $result = [System.Windows.MessageBox]::Show("The Device Name `"$($WPFControl_tbDeviceName.Text)`" already exists", "Double Entry!", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        } elseif ($Script:DeviceSecrets | Where Secret -eq $($Script:B32Secret)) {
            $result = [System.Windows.MessageBox]::Show("The Secret already exists!`nGenerate a new secret", "Double Entry!", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        } else {
            if (-Not $WPFControl_btnSaveOtp.IsEnabled) { $WPFControl_btnSaveOtp.IsEnabled = $true }
            $Script:DeviceSecrets += [PSCustomObject]@{
                DeviceName = $($WPFControl_tbDeviceName.Text)
                Secret     = $($Script:B32Secret)
            }
            $WPFControl_lvOtps.ItemsSource = $Script:DeviceSecrets
        }
        $Script:Saved = $false
        Clean-GUIQR
    }
)

$WPFControl_tbUsername.Add_KeyDown{
    param(
        [Parameter(Mandatory)][Object]$sender,
        [Parameter(Mandatory)][Windows.Input.KeyEventArgs]$e
    )
    #Write-Verbose "Sender: $($sender | Out-String)"
    #Write-Verbose "E: $($e | Out-String)"
    if ($e.Key -eq "Return") {
        Write-Verbose "Enter"
        Update-Gui
        Execute-SearchADUser
    }
}


$WPFControl_tbAttribute.add_TextChanged( 
    { 
        Write-Verbose "tbAttribute Text Changed"
        $Script:Attribute = $WPFControl_tbAttribute.Text
    }
)

$WPFControl_tbDeviceName.add_TextChanged( 
    { 
        Write-Verbose "tbDeviceName Text Changed"
        Update-Gui
        Validate-AddSecret
        Validate-GenerateQR
    }
)

$WPFControl_tbGateway.add_TextChanged( 
    { 
        Write-Verbose "tbGateway Text Changed"
        Update-Gui
        Validate-AddSecret
        Validate-GenerateQR
    }
)
$WPFControl_tbSecret.add_TextChanged( 
    { 
        Write-Verbose "tbSecret Text Changed"
        Update-Gui
        Validate-AddSecret
        Validate-GenerateQR
    }
)

$WPFControl_btnSearch.Add_Click( 
    { # btnSearch Click Action
        Write-Verbose "btnSearch Clicked"
        Update-Gui
        Execute-SearchADUser
    }
)

$WPFControl_lvUsernames.add_SelectionChanged( 
    { 
        Write-Verbose "lvUsernames Selection Changed"
        Update-Gui
        Clean-GUIQR
        $SelectedItem = $WPFControl_lvUsernames.SelectedItem
        if (-Not [String]::IsNullOrEmpty($($SelectedItem.Attribute))) {
            $Script:DeviceSecrets = @()
            $Script:DeviceSecrets += Extract-Attribute -Data $SelectedItem.Attribute
            $WPFControl_lvOtps.ItemsSource = $Script:DeviceSecrets
            if (-Not $WPFControl_tbDeviceName.IsEnabled) { $WPFControl_tbDeviceName.IsEnabled = $true }
            if (-Not $WPFControl_btnLoadOtp.IsEnabled) { $WPFControl_btnLoadOtp.IsEnabled = $true }
        } else {
            $WPFControl_lvOtps.ItemsSource = $null
            if ($WPFControl_tbDeviceName.IsEnabled) { $WPFControl_tbDeviceName.IsEnabled = $false }
            if ($WPFControl_btnLoadOtp.IsEnabled) { $WPFControl_btnLoadOtp.IsEnabled = $false }
        }
        
        
    }
)

$WPFControl_lvOtps.add_SelectionChanged( 
    { 
        Write-Verbose "lvOtps Selection Changed" 
        Update-Gui
        $SelectedItem = $WPFControl_lvOtps.SelectedItem
        Write-Verbose "Selected item: $SelectedItem"
        if ([String]::IsNullOrEmpty($($SelectedItem.Secret))) {
            if ($WPFControl_btnDeleteOtp.IsEnabled) { $WPFControl_btnDeleteOtp.IsEnabled = $false }
        } else {
            if (-Not $WPFControl_btnDeleteOtp.IsEnabled) { $WPFControl_btnDeleteOtp.IsEnabled = $true }
        }
    }
)

$WPFControl_btnGenerateQR.Add_Click( 
    { # btnGenerateQR Click Action
        Update-Gui
        Clean-GUIQRImage
        if ($QRGeneration) {
            Load-QR
            Update-Gui
            $SelectedItem = $WPFControl_lvUsernames.SelectedItem
            $SamAccountName = $SelectedItem.SamAccountName
            $DeviceName = $WPFControl_tbDeviceName.text
            $Target = $WPFControl_tbGateway.text
            $NetBIOSName = $SelectedItem.NetBIOSName
            
            $OTPUri = "otpauth://totp/"
            #Previous
            #$OTPUri += [Uri]::EscapeDataString($("{0}@{1}@{2}" -f $NetBIOSName,$SamAccountName,$Target))
            #Current 13.0 generation
            $OTPUri += [Uri]::EscapeDataString($("{0}@{1}" -f $SamAccountName, $Target))
            $OTPUri += "?secret={0}&device={1}" -f $Script:B32Secret, $DeviceName
            Write-Verbose "OTP Uri: $OTPUri"
            $Script:QRImage = New-QRCodeURI -URI $OTPUri -OutStream
            #$ImgSource = New-Object System.Drawing.Bitmap($QRImage)
            #$Hbitmap = $ImgSource.GetHbitmap()
            #[System.Windows.Media.ImageSource]$QRImageSource = [System.Windows.Interop.Imaging]::CreateBitmapSourceFromHBitmap($Hbitmap, [System.IntPtr]::Zero, [System.Windows.Int32Rect]::Empty, [System.Windows.Media.Imaging.BitmapSizeOptions]::FromEmptyOptions());
            
            $QRImageSource = New-Object System.Windows.Media.Imaging.BitmapImage
            $QRImageSource.BeginInit()
            $QRImageSource.StreamSource = $QRImage
            $QRImageSource.EndInit() 
            #$QRImageSource.Freeze()
            $WPFControl_ImgQR.Source = $QRImageSource
            $Script:Saved = $false
            Show-QR
        } else {
            $result = [System.Windows.MessageBox]::Show("The PowerShell Module `"QRCodeGenerator`" was NOT Found!`nQR Code generation is disabled.", "QRCodeGenerator Module", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Exclamation)
        }
    }
)

$WPFControl_btnExportQR.Add_Click( 
    { # btnExportQR Click Action
        try {
            $SelectedItem = $WPFControl_lvUsernames.SelectedItem
            $PNGPath = Save-File -FileName $("{0}_{1}_{2}.png" -f $SelectedItem.SamAccountName, $WPFControl_tbDeviceName.text, $WPFControl_tbGateway.text)
            Write-Verbose "PNGPath: $PNGPath"
            if (Test-Path (Split-Path -Path $PNGPath -Parent | Resolve-Path).Path) {
                [System.IO.File]::WriteAllBytes($PNGPath, $($Script:QRImage.ToArray()))
                $WPFControl_lblQR.Content = "Exported Successfully!"
            } else {
                $WPFControl_lblQR.Content = "Export Failed!"
            }
        } catch {
            Write-Verbose "$($_.Exception.Message)"
            $WPFControl_lblQR.Content = "Export Failed!"
        }
    }
)

#endregion Event handlers

# Show/Run the App
$App.Run($Form)
