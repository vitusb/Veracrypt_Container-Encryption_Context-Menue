<# :# PowerShell comment protecting the Batch section
@echo off
:# Disabling argument expansion avoids issues with ! in arguments.
:# --- Encoded in utf-8 for öäüÖÄÜ ---
:# EncryptData.ps1 by Mounir IDRASSI
:# Redesigned and hardened by Veit Berwig in 04/2026
:# Changelog
:#    20260409
:#      - Powershell Inline-Code without temp-file creation
:#        Source: https://stackoverflow.com/a/61821651
:#      - german / english language support
:#      - additional check for container path existence
:#      - secure password verification dialog
:#      - disabling telmetry by script-environment of calling-script
:#          DOTNET_CLI_TELEMETRY_OPTOUT=1
:#          POWERSHELL_TELEMETRY_OPTOUT=1
:#      - cleanup environment after password-operations
:#      - cleanup Powershell-History on exit
:#      - Support for special chars in path-names.

setlocal EnableExtensions DisableDelayedExpansion

:# Prepare the batch arguments, so that PowerShell parses them correctly
set ARGS=%*
if defined ARGS set ARGS=%ARGS:"=\"%
if defined ARGS set ARGS=%ARGS:'=''%
if defined ARGS set ARGS=%ARGS:$=`$%
if defined ARGS set ARGS=%ARGS:[=``[%
if defined ARGS set ARGS=%ARGS:]=``]%

:# The ^ before the first " ensures that the Batch parser does not
:# enter quoted mode there, but that it enters and exits quoted mode
:# for every subsequent pair of ". This in turn protects the possible
:# special chars & | < > within quoted arguments. Then the \ before
:# each pair of " ensures that PowerShell's C command line parser
:# considers these pairs as part of the first and only argument
:# following -c. Cherry on the cake, it's possible to pass a " to PS
:# by entering two "" in the bat args.

:# --- Batch-Code --- BEGIN ---
set DOTNET_CLI_TELEMETRY_OPTOUT=1
set POWERSHELL_TELEMETRY_OPTOUT=1
REM :: Passing scriptname into env in order to use it in PS-code
REM :: because other functions from PS to retrieve scriptname from
REM :: inline-PS will not work in inline-code.
set MYSCRIPT=%~n0
set MYSCRIPTEXT=%~nx0
:# --- Batch-Code ---  END  ---

PowerShell.exe -ep bypass -noprofile -c ^"Invoke-Expression ('^& {' + (get-content -raw '%~f0') + '} %ARGS%')"
:end
echo.
echo PowerShell Exit Code = %ERRORLEVEL%
exit /b
GOTO :EOF
###############################################################################
End of the PS comment around the Batch section; Begin the PowerShell section #>

# ####################################################################
# Powershell Encoding
# ####################################################################
# The PS script actually needs to be encoded with UTF-8 (BOM) so that
# umlauts are displayed correctly during program execution. However,
# this overrides the inline recognition of PS code in the batch file;
# therefore, BOM encoding is NOT used here.
# ####################################################################
# Workaround:
# https://stackoverflow.com/q/65305790/#comment115513164_65307397
# Character set in VBA (0 - 127)
# https://docs.microsoft.com/de-de/office/vba/language/reference/user-interface-help/character-set-0127
# Character set in VBA (128–255)
# https://docs.microsoft.com/de-de/office/vba/language/reference/user-interface-help/character-set-128255
# ####################################################################
# BACKSPACE Chr(8)    / TAB     Chr(9)
# LINEFEED  Chr(10)   / RETURN  Chr(13)
#
# 196 Ä     Chr(196)  / 228 ä   Chr(228)
# 213 Ö     Chr(213)  / 246 ö   Chr(246)
# 220 Ü     Chr(220)  / 252 ü   Chr(252)
# 223 ß     Chr(223)  / 128 €   Chr(128)
# ####################################################################
# Example (in German):
# Write-Host('Erzeuge Verkn' + "$([char]252)" + 'pfung') oder
# Write-Host("Erzeuge Verkn$([char]252)pfung")
# ####################################################################
# Tips:
#       - Multiple colors in one Write-Host line:
#         https://github.com/EvotecIT/PSWriteColor

# Parameters
param(
    [string] $inputPath,
    [string] $containerPath
)

# Get i myself ...
$IMySelf = $env:MYSCRIPT
$host.UI.RawUI.WindowTitle = "Veracrypt Container-Encryption";

# $DNTOO = [Environment]::GetEnvironmentVariable("DOTNET_CLI_TELEMETRY_OPTOUT")
# $PSTOO = [Environment]::GetEnvironmentVariable("POWERSHELL_TELEMETRY_OPTOUT")
# Write-Host "[DEBUG] POWERSHELL_TELEMETRY_OPTOUT: $DNTOO" -ForegroundColor Blue
# Write-Host "[DEBUG] POWERSHELL_TELEMETRY_OPTOUT: $PSTOO" -ForegroundColor Blue
# Write-Host "[DEBUG]: inputPath ist: $inputPath" -ForegroundColor Blue

Write-Host "##################################" -ForegroundColor Yellow
Write-Host "# Veracrypt Container-Encryption #" -ForegroundColor Yellow
Write-Host "##################################" -ForegroundColor Yellow
Write-Host ""

# Check required params
if ([string]::IsNullOrEmpty($inputPath)) {
    Write-Host "###############################################################################"
    Write-Host "# ${IMySelf}: Encrypt a folder into a container with VeraCrypt !"
    Write-Host "###############################################################################"
    Write-Host "${IMySelf} ""source folder"" ""target-container"""
    Write-Host ""
    Write-Host "${IMySelf} -inputPath ""C:\MyFolder"" -containerPath ""D:\MyContainer.hc"""
    Write-Host "${IMySelf} ""C:\MyFolder"" ""D:\MyContainer.hc"""
    Start-Sleep -s 6
    exit 1;
}

# Check the required params
# If $containerPath is IsNullOrEmpty, then we use
# "${inputPath}.hc" as $containerPath and do not raise an error.
#
# if ([string]::IsNullOrEmpty($containerPath)) {
#     Write-Host "###############################################################################"
#     Write-Host "# ${IMySelf}: Encrypt a folder into a container with VeraCrypt !"
#     Write-Host "###############################################################################"
#     Write-Host "${IMySelf} ""source folder"" ""target-container"""
#     Write-Host ""
#     Write-Host "${IMySelf} -inputPath ""C:\MyFolder"" -containerPath ""D:\MyContainer.hc"""
#     Write-Host "${IMySelf} ""C:\MyFolder"" ""D:\MyContainer.hc"""
#     Start-Sleep -s 6
#     exit 1;
# }

# VeraCrypt absolute program-path
$veracryptPath = "C:\Program Files\VeraCrypt"
# VeraCrypt main program
$veraCryptExe = Join-Path $veracryptPath "VeraCrypt.exe"
# VeraCrypt formatter
$veraCryptFormatExe = Join-Path $veracryptPath "VeraCrypt Format.exe"
# Constants for calculating the size of the exFAT file system
$InitialVBRSize = 32KB
$BackupVBRSize = 32KB
$InitialFATSize = 128KB
$ClusterSize = 32KB      # TODO: Make this value configurable
$UpCaseTableSize = 128KB # Typical size

# Check if Veracrypt exists ...
if (-not (Test-Path -LiteralPath "$veraCryptExe")) {
    Write-Host "The program `"Veracrypt`" does not exist ..." -ForegroundColor Red
    Write-Host "Please define a correct path for the executable" -ForegroundColor Red
    Write-Host "in this script or install the program `"Veracrypt`" !!" -ForegroundColor Red
    Start-Sleep -s 6
    exit 1
}

# Check if Veracrypt Formatter exists ...
if (-not (Test-Path -LiteralPath "$veraCryptFormatExe")) {
    Write-Host "The program `"VeraCrypt Format`" does not exist ..." -ForegroundColor Red
    Write-Host "Please define a correct path for the executable" -ForegroundColor Red
    Write-Host "in this script or install the program `"VeraCrypt`" !!" -ForegroundColor Red
    Start-Sleep -s 6
    exit 1
}

<#
.SYNOPSIS
This PowerShell script is used to create a VeraCrypt container with
minimal size to hold a copy of the given input file or directory.

Original-Version:
https://sourceforge.net/projects/veracrypt/files/Contributions/EncryptData.ps1

.DESCRIPTION
This script takes as input a file path or directory path and a
container path. If the container path is not specified, it defaults
to the same as the input path with a ".hc" extension. The script
calculates the minimal size needed to hold the input file or directory
in a VeraCrypt container. It then creates a VeraCrypt container with
the specified path and the calculated size using exFAT filesystem.
Finally, the container is mounted, the input file or directory is
copied to the container and the container is dismounted.

.PARAMETER inputPath
The file path or directory path to be encrypted in the VeraCrypt
container.

.PARAMETER containerPath
The desired path for the VeraCrypt container. If not specified, it
defaults to the same as the input path with a ".hc" extension.

.EXAMPLE
.\EncryptData.ps1 -inputPath "C:\MyFolder" -containerPath "D:\MyContainer.hc"
.\EncryptData.ps1 "C:\MyFolder" "D:\MyContainer.hc"
.\EncryptData.ps1 "C:\MyFolder"

.NOTES
Author..........: Mounir IDRASSI
Email...........: mounir.idrassi@idrix.fr
Date............: 20240726
License.........: This script is licensed under the Apache License 2.0
Modified........: 20250323
Modified_by.....: Veit Berwig

#>

# ####################################################################
# Safely compares two SecureString objects without decrypting them.
# Outputs $true if they are equal, or $false otherwise.
# Source: https://stackoverflow.com/a/48810852
# Usage:
# $theyMatch = Compare-SecureString $cred1.Password $cred2.Password
# if ( $theyMatch ) {
#    ...
# }
# ####################################################################
function Compare-SecureString {
  param(
    [Security.SecureString]
    $secureString1,
    
    [Security.SecureString]
    $secureString2
  )
  try {
    $bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString1)
    $bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString2)
    $length1 = [Runtime.InteropServices.Marshal]::ReadInt32($bstr1,-4)
    $length2 = [Runtime.InteropServices.Marshal]::ReadInt32($bstr2,-4)
    if ( $length1 -ne $length2 ) {
      return $false
    }
    for ( $i = 0; $i -lt $length1; ++$i ) {
      $b1 = [Runtime.InteropServices.Marshal]::ReadByte($bstr1,$i)
      $b2 = [Runtime.InteropServices.Marshal]::ReadByte($bstr2,$i)
      if ( $b1 -ne $b2 ) {
        return $false
      }
    }
    return $true
  }
  finally {
    if ( $bstr1 -ne [IntPtr]::Zero ) {
      [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)
    }
    if ( $bstr2 -ne [IntPtr]::Zero ) {
      [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
    }
  }
}

function ConvertTo-AbsolutePath {
    param (
        [Parameter(Mandatory=$true)]
        [string] $Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    
    return Join-Path -Path (Get-Location) -ChildPath $Path
}

# The Function "Get-Script-Name" does not work on scripts, running
# as inline-code in Batch-files. So we rebuilt this functionality
# by a variable-substitution in the calling batch-script (see above).
#
# Function Get-Script-Name() {
#     $filename = $MyInvocation.ScriptName | Split-Path -Leaf
#     if ($filename -match ".") {
#         $filename = $filename.Substring(0, $filename.LastIndexOf("."))
#     }
#     return $filename
# }

# Convert input path to fully qualified path
$inputPath = ConvertTo-AbsolutePath -Path $inputPath

# Check if input path exists
if (-not (Test-Path $inputPath)) {
    Write-Host "The specified input path does not exist."
    Write-Host "Please provide a valid input path."
    Start-Sleep -s 6
    exit 1
}

$inputPath = (Resolve-Path -Path $inputPath).Path

# Set container path if not specified
if ([string]::IsNullOrWhiteSpace($containerPath)) {
    $containerPath = "${inputPath}.hc"
    $containerPath = ConvertTo-AbsolutePath -Path $containerPath
} else {
    $containerPath = ConvertTo-AbsolutePath -Path $containerPath
}

#: Write-Host "[DEBUG]: containerPath is: $containerPath" -ForegroundColor Blue

# Check if container path already exists
if (Test-Path -LiteralPath $containerPath) {
    Write-Host "The specified container path already exists."
    Write-Host "Please specify a unique path for the new container."
    Start-Sleep -s 6
    exit 1
}

# Get the full qualified part of a path from a
# full qualified given path of a file
$containerPathOF = Split-Path -Path "$containerPath" -Parent
# Check if path of container already exists
if (-not (Test-Path "$containerPathOF")) {
    Write-Host "The specified container path does not exist !"
    Write-Host "Please specify an existing path for the new container."
    Start-Sleep -s 6
    exit 1
}

function Get-ExFATSizeRec {
    param(
        [string] $Path,
        [uint64] $TotalSize
    )

    # Constants
    $BaseMetadataSize = 32
    $DirectoryEntrySize = 32

    try {
        # Get the item (file or directory) at the provided path
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop

        # Calculate metadata size
        $fileNameLength = $item.Name.Length
        $metadataSize = $BaseMetadataSize + ($fileNameLength * 2)

        # Calculate directory entries
        if ($fileNameLength -gt 15) {
            $numDirEntries = [math]::Ceiling($fileNameLength / 15) + 1
        } else {
            $numDirEntries = 2
        }
        $dirEntriesSize = $numDirEntries * $DirectoryEntrySize

        # Add metadata, file size, and directory entries size to $TotalSize
        $TotalSize += $metadataSize + $dirEntriesSize

        if ($item.PSIsContainer) {
            # It's a directory
            $childItems = Get-ChildItem -LiteralPath $Path -ErrorAction Stop

            foreach ($childItem in $childItems) {
                # Recursively call this function for each child item
                $TotalSize = Get-ExFATSizeRec -Path $childItem.FullName -TotalSize $TotalSize
            }
        } else {
            # It's a file

            # Calculate actual file size and round it up to the nearest multiple of $ClusterSize
            $fileSize = $item.Length
            $totalFileSize = [math]::Ceiling($fileSize / $ClusterSize) * $ClusterSize

            # Add metadata, file size, and directory entries size to $TotalSize
            $TotalSize += $totalFileSize
        }
    } catch {
        Write-Error "Error processing element in path ${Path}: $_"
    }

    return $TotalSize
}

function Get-ExFATSize {
    param(
        [string] $Path
    )

    try {
        # Initialize total size
        $totalSize = $InitialVBRSize + $BackupVBRSize + $InitialFATSize + $UpCaseTableSize

        # Call the recursive function
        $totalSize = Get-ExFATSizeRec -Path $Path -TotalSize $totalSize

        # Add the root directory to $totalSize
        $totalSize += $ClusterSize

        # Calculate the size of the Bitmap Allocation Table
        $numClusters = [math]::Ceiling($totalSize / $ClusterSize)
        $bitmapSize = [math]::Ceiling($numClusters / 8)
        $totalSize += $bitmapSize

        # Adjust the size of the FAT
        $fatSize = $numClusters * 4
        $totalSize += $fatSize - $InitialFATSize
		
        # Add safety factor to account for potential filesystem overhead
        # For smaller datasets (<100MB), we add 1% or 64KB (whichever is larger)
        # For larger datasets (>=100MB), we add 0.1% or 1MB (whichever is larger)
        # This scaled approach ensures adequate extra space without excessive overhead
        $safetyFactor = if ($totalSize -lt 100MB) {
            [math]::Max(64KB, $totalSize * 0.01)
        } else {
            [math]::Max(1MB, $totalSize * 0.001)
        }
        $totalSize += $safetyFactor

        # Return the minimum disk size needed to store the exFAT filesystem
        return $totalSize

    } catch {
        Write-Error "Error calculating exFAT size for path ${Path}: $_"
        return 0
    }
}

# Calculate size of the container
$containerSize = Get-ExFATSize -Path $inputPath

# Convert to MB and round up to the nearest MB
$containerSize = [math]::Ceiling($containerSize / 1MB)

Write-Host ("Containersize: $containerSize MB") -ForegroundColor Yellow

# Add extra space for VeraCrypt headers, reserved areas, and potential alignment requirements
# We use a sliding scale to balance efficiency for small datasets and adequacy for large ones:
# - For very small datasets (<10MB), add 1MB
# - For small to medium datasets (10-100MB), add 2MB
# - For larger datasets (>100MB), add 1% of the total size
# This approach ensures sufficient space across a wide range of dataset sizes
if ($containerSize -lt 10) {
    $containerSize += 1  # Add 1 MB for very small datasets
} elseif ($containerSize -lt 100) {
    $containerSize += 2  # Add 2 MB for small datasets
} else {
    $containerSize += [math]::Ceiling($containerSize * 0.01)  # Add 1% for larger datasets
}

# Ensure a minimum container size of 2 MB
$containerSize = [math]::Max(2, $containerSize)

# Specify encryption algorithm, and hash algorithm
$encryption = "AES"
$hash = "sha512"

# Be aware, that passwords are not really secure by shell-commandlines.
# Details: https://get-powershellblog.blogspot.com/2017/06/how-safe-are-your-strings.html
#
$Password01  = Read-Host ("Please enter password") -AsSecureString
$Password02  = Read-Host ("Please repeat password") -AsSecureString

$PWMatch = Compare-SecureString $Password01 $Password02
if ( $PWMatch ) {
    $password = $Password02
} Else {
    Write-Host ("")
    Write-Host -ForegroundColor Red ("The two passwords do not match !")
    Write-Host -ForegroundColor Red ("Pay attention to CAPITAL and lowercase and")
    Write-Host -ForegroundColor Red ("avoid umlauts or special characters.")
    Write-Host -ForegroundColor Red ("I cancel the process !")
    Start-Sleep -s 6
    exit 1
}

# Create a PSCredential object
$cred = New-Object System.Management.Automation.PSCredential ("username", $password)

Write-Host "Creating VeraCrypt Container `"$containerPath`" ..."

# Create file container using VeraCrypt Format
# TODO: Add a switch to VeraCrypt Format to allow specifying the cluster size to use for the container
$veraCryptFormatArgs = "/create `"$containerPath`" /size `"${containerSize}M`" /password $($cred.GetNetworkCredential().Password) /encryption $encryption /hash $hash /filesystem `"exFAT`" /quick /silent"
Start-Process $veraCryptFormatExe -ArgumentList $veraCryptFormatArgs -NoNewWindow -Wait

# Check that the container was successfully created
if (-not (Test-Path -LiteralPath $containerPath)) {
    Write-Host "An error occurred while creating the VeraCrypt container."
    Start-Sleep -s 6
    exit 1
}

# Get a list of currently used drive letters
$driveLetter = Get-Volume | Where-Object { $_.DriveLetter -ne $null } | Select-Object -ExpandProperty DriveLetter

# Find the first available drive letter
$unusedDriveLetter = (70..90 | ForEach-Object { [char]$_ } | Where-Object { $_ -notin $driveLetter })[0]

# If no available drive letter was found, print an error message and exit the script
if ($null -eq $unusedDriveLetter) {
    # delete the file container that was created
    Remove-Item -Path $containerPath -Force
    Write-Error "No available drive letters were found."
    Write-Error "Please release a drive letter and try again."
    Start-Sleep -s 6
    exit 1
}

Write-Host "Mount the newly created VeraCrypt container into the system ..."

# Mount the container to the chosen drive letter as removable media
Start-Process $veraCryptExe -ArgumentList "/volume `"$containerPath`" /letter $unusedDriveLetter /m rm /password $($cred.GetNetworkCredential().Password) /quit" -NoNewWindow -Wait

# Check if the volume has been mounted successfully
$mountedDriveRoot = "${unusedDriveLetter}:\"
if (-not (Test-Path -LiteralPath $mountedDriveRoot)) {
    # Volume mount failed
    Write-Error "The volume or image could not be mounted."
    Write-Error "Please make sure that the VeraCrypt.exe program is working correctly."
    # delete the file container that was created
    Remove-Item -LiteralPath $containerPath -Force
    Start-Sleep -s 6
    exit 1
}

Write-Host "Copy data into the mounted VeraCrypt container ..."

# Copy the file or directory to the mounted drive
if (Test-Path -LiteralPath $inputPath -PathType Container) {
    # For directories
    Copy-Item -LiteralPath $inputPath -Destination "$($unusedDriveLetter):\" -Recurse
} else {
    # For files
    Copy-Item -LiteralPath $inputPath -Destination "$($unusedDriveLetter):\"
}

Write-Host "Copying completed. The VeraCrypt container is being disconnected from the system ..."

# give some time for the file system to flush the data to the disk
Start-Sleep -Seconds 5

# Dismount the volume
Start-Process $veraCryptExe -ArgumentList "/dismount $unusedDriveLetter /quit" -NoNewWindow -Wait

Write-Host "The VeraCrypt container was created successfully."

# Fill var-content with random data
$password = -join ((65..90) + (97..122) | Get-Random -Count 40 | % {[char]$_})

# --- Powershell Cleanup history --- BEGIN ---

  # Cleanup history of Powershell and CMD-Shells from here:
  # https://stackoverflow.com/a/38807689
  
  # [CmdletBinding(ConfirmImpact='High', SupportsShouldProcess)]
  # param(    
  # )
  
  # Debugging: For testing you can simulate not having PSReadline loaded with
  #            Remove-Module PSReadline -Force
  $havePSReadline = ($null -ne (Get-Module -EA SilentlyContinue PSReadline))
  if ($havePSReadline) { Write-Host "PSReadline present: $havePSReadline" -f red }
  
  # $target = if ($havePSReadline) { "entire command history, including from previous sessions" } else { "command history" } 
  # if (-not $pscmdlet.ShouldProcess($target))
  # {
  #       return
  # }

  if ($havePSReadline) {
    # Clear-Host
    # Remove PSReadline's saved-history file.
    if (Test-Path -LiteralPath (Get-PSReadlineOption).HistorySavePath) { 
      # Abort, if the file for some reason cannot be removed.
      Remove-Item -EA Stop (Get-PSReadlineOption).HistorySavePath 
      # To be safe, we recreate the file (empty). 
      $null = New-Item -Type File -Path (Get-PSReadlineOption).HistorySavePath
    }
    # Clear PowerShell's own history 
    Clear-History

    # Clear PSReadline's *session* history.
    # General caveat (doesn't apply here, because we're removing the saved-history file):
    #   * By default (-HistorySaveStyle SaveIncrementally), if you use
    #    [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory(), any sensitive
    #    commands *have already been saved to the history*, so they'll *reappear in the next session*. 
    #   * Placing `Set-PSReadlineOption -HistorySaveStyle SaveAtExit` in your profile 
    #     SHOULD help that, but as of PSReadline v1.2, this option is BROKEN (saves nothing). 
    [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()

  } else { 
    # Without PSReadline, we only have a *session* history.
    # Clear-Host
    # Clear the doskey library's buffer, used pre-PSReadline. 
    # !! Unfortunately, this requires sending key combination Alt+F7.
    # Thanks, https://stackoverflow.com/a/13257933/45375
    $null = [system.reflection.assembly]::loadwithpartialname("System.Windows.Forms")
    [System.Windows.Forms.SendKeys]::Sendwait('%{F7 2}')

    # Clear PowerShell's own history 
    Clear-History
}
# --- Powershell Cleanup history ---  END  ---
Start-Sleep -s 4