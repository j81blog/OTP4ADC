# OTP4ADC
Manage OTP tokens used by the Citrix ADC

For more details, view [my blog article](https://blog.j81.nl/2020/09/29/manage-native-otp-tokens-via-windows/)

## GUI

Just execute __"OTP4ADC.ps1"__ and you will be presented with a GUI.

## CommandLine

You can run and set option via the commandline, without using the GUI. You need to specify multiple options

```PowerShell
# CLI: Edit one user 
C:\OTP4ADC\OTP4ADC.ps1 -GatewayURI <String> -Attribute <String> -Username <String> -DeviceName <String> -ExportPath <String> [-QRSize <Int32>] [-TokenText <String>] [-ReplaceTokens] [-Thumbprint <String>]

# CLI: Edit one user with specifying your own secret
C:\OTP4ADC\OTP4ADC.ps1 -GatewayURI <String> -Attribute <String> -Username <String> -DeviceName <String> -Secret <String> [-QRSize <Int32>] [-TokenText <String>] [-ReplaceTokens] [-Thumbprint <String>]

# CLI: Edit one user while having no write permissions to AD
C:\OTP4ADC\OTP4ADC.ps1 -NoAD -GatewayURI <String> -Username <String> -DeviceName <String> -ExportPath <String> [-QRSize <Int32>] [-TokenText <String>] [-Thumbprint <String>]

#CLI: Bulk import a CSV (with or without specifying your own secret)
C:\OTP4ADC\OTP4ADC.ps1 -GatewayURI <String> -Attribute <String> -CsvPath <FileInfo> [-Delimiter <String>] [-ExportPath <String>] [-QRSize <Int32>] [-TokenText <String>] [-ReplaceTokens] [-Thumbprint <String>]
```

__EXAMPLE:__ add edit a user 

Optional parameters are:
* "-Secret" => Specify your own __BASE32__ secret
* "-QRSize" => option to change the default image resolution
* "-TokenText" => 1, 2 or 3. How the  text is being presented in the Authenticator
* "-ReplaceTokens" => to "overwrite" the current specified secrets for the given user (default will be added to the list)
* "-Thumbprint" => __Only usable when Powershell Core (v7 or higner) is used__ Option to specify the thumbprint of a certificate used to encrypt the secrets in AD

```PowerShell
C:\OTP4ADC\OTP4ADC.ps1 -attribute userParameters -GatewayURI portal.domain.com -username john.doe@domain.com -DeviceName Mobile -ExportPath C:\export
```

*__EXPLANATION:__ Edit a user named **"john.doe@domain.com"** and add a newly generated secret for device **"Mobile"** to the attribute **"userParameters"**. When done export the QR PNG to the directory __"C:\export"__*

You can also bulk import a csv (with or without specifying your own secrets)

__EXAMPLE:__ Import a CSV 

CSV file (users.csv) **without** Secrets

```CSV
"Username","DeviceName"
"john.doe@domain.com","Mobile"
"jane.doe@domain.com","Mobile"
```

CSV file (users.csv) **with** Secrets

```CSV
"Username","DeviceName","Secret"
"john.doe@domain.com","Mobile","BASE32SECRET"
"jane.doe@domain.com","Mobile","BASE32SECRET"
```

Optional parameters are:
* "-Delimiter" => Specifying a different delimiter for your CSV than the "default" comma ","
* "-ExportPath" => where the QR-images of the generated secrets are being stored
* "-QRSize" => option to change the default image resolution
* "-TokenText" => 1, 2 or 3. How the  text is being presented in the Authenticator
* "-ReplaceTokens" => to "overwrite" the current specified secrets for the given user (default will be added to the list)
* "-Thumbprint" => __Only usable when Powershell v7 or higner is used)__ Option to specify the thumbprint of a certificate used to encrypt the secrets in AD

You can "import" the CSV by using the "-FileImport" parameter. 

*__NOTE:__ When not defining your own secret, please don't forget to specify an "ExportPath" by specifying the "-ExportPath" parameter!*

*__NOTE:__ If secrets are detected the QR-image won't be generated!*

```PowerShell
C:\OTP4ADC\OTP4ADC.ps1 -attribute userParameters -GatewayURI portal.domain.com -ExportPath C:\export -FileImport
```
*__EXPLANATION:__ Edit all users specified tin the CSV-file (add a newly generated secret if omitted for device specified in the CSV) to the attribute **"userParameters"**.*

*The __GatewayURI__ is specified as portal.domain.com.*

*When done export the QR PNG to the directory __"C:\export"__, if a new secret was generated and not specified in the CSV.*