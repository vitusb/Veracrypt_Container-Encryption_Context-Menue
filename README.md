# Veracrypt Container-Encryption Context-Menue
Container-Encryption for directory-entries by context-menu and command-line

### This script is based on the Powershell-Code "[EncryptData.ps1](https://sourceforge.net/projects/veracrypt/files/Contributions/)" by [Mounir IDRASSI](https://github.com/idrassi) with some enhancements.

<img width="775" height="403" alt="grafik" src="https://github.com/user-attachments/assets/80f96e50-dfd3-4a59-bd8f-9405009bc86c" />

### - Features -
- cryptography<br>
  * Mode: XTS
  * PKCS-5 Profile: HMAC-SHA-512
  * Algorithm: AES-256<br>
- bat-script with embedded Powershell Inline-Code without temp-file creation
- german / english language support
- additional check for container path existence
- secure password verification dialog
- disabling telmetry by script-environment of calling-script<br>
  * DOTNET_CLI_TELEMETRY_OPTOUT=1
  * POWERSHELL_TELEMETRY_OPTOUT=1</br>
- cleanup environment after password-operations
- cleanup Powershell-History on exit
- Support for special chars like $"[]{}, etc. in path-names.

### - Installation (an installer will be provided in future) -
- copy all stuff into "%windir%" ...
- double-klick the corresponding reg-file for your language ("EncryptData_DirEN.reg" or "EncryptData_DirDE.reg") with admin-rights.

<br>that's it 😸

