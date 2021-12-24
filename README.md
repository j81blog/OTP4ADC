# OTP4ADC
Manage OTP tokens used by the Citrix ADC

For more details, view [my blog article](https://blog.j81.nl/2020/09/29/manage-native-otp-tokens-via-windows/)

## GUI

Just execute 'OTP4ADC.ps1' and you will be presented with a GUI.

## CommandLine

You can run and set option via the commandline, without using the GUI. You need to specify multiple options

```
OTP4ADC.ps1 -GatewayURI <String> -Attribute <String> -Username <String> -DeviceName <String> -ExportPath <String> [-QRSize <Int32>] [-TokenText <String>] [-Secret <String>] [-ReplaceTokens] [-Thumbprint <String>] [<CommonParameters>]
```

Example, add edit a user named **"john.doe@domain.com"** and add a newly generated secret for device **"Mobile"** to the attribute **"userParameters"**. When done export the QR PNG to the directory **"C:\export"**

```PowerShell
C:\Scripts\OTP4ADC.ps1  -attribute userParameters -GatewayURI portal.domain.com -username john.doe@domain.com -DeviceName Mobile -ExportPath C:\export
```

Same but you could also specify or use a csv with data

```PowerShell
$exportPath = "C:\export"
$gatewayURI = "portal.domain.com"
$attribute = "userParameters"

$csvData = @"
"Username","DeviceName"
"john.doe@domain.com","Mobile"
"jane.doe@domain.com","Mobile"
"@ | ConvertFrom-CSV

New-Item -Path $exportPath -ItemType Directory -Force | Out-Null

$results = @()
ForEach ($item in $csvData) {
    $results += C:\Scripts\OTP4ADC.ps1  -attribute $attribute -GatewayURI $gatewayURI -username $item.Username -DeviceName $item.DeviceName -ExportPath $exportPath    
}
$results
```