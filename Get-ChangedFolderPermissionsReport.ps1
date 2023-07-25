[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, HelpMessage="Enter the folder path to be analyzed.")]
    [string]$TargetFolderPath,
    
    [Parameter(Mandatory=$true, Position=1, HelpMessage="Enter the destination of the output csv file.")]
    [string]$OutputFile,

    [Parameter(Mandatory=$false, Position=2, HelpMessage="Enter the users to exclude, separated by comma.")]
    [string[]]$ExcludeUsers = @(),

    [switch]$Help
)

if ($Help) {
    Write-Host "This script analyzes a folder path and generates a CSV file report with folders that have permissions different from their parent folder or folders that have permissions not inherited from the parent folder."
    Write-Host "It takes two mandatory parameters, a target folder path to be analyzed and a destination for the output csv file. Additionally, you can provide optional users to exclude from the output."
    Write-Host "Usage: .\Get-ChangedFolderPermissionsReport.ps1 -TargetFolderPath 'C:\path\to\analyze' -OutputFile 'C:\path\to\output.csv' -ExcludeUsers 'NT AUTHORITY\SYSTEM', 'CREATOR OWNER', 'NT SERVICE\TrustedInstaller'"
    return
}

# Access mask dictionary
$accessMask = [ordered]@{
  [uint32]'0x80000000' = 'GenericRead'
  [uint32]'0x40000000' = 'GenericWrite'
  [uint32]'0x20000000' = 'GenericExecute'
  [uint32]'0x10000000' = 'GenericAll'
  [uint32]'0x02000000' = 'MaximumAllowed'
  [uint32]'0x01000000' = 'AccessSystemSecurity'
  [uint32]'0x00100000' = 'Synchronize'
  [uint32]'0x00080000' = 'WriteOwner'
  [uint32]'0x00040000' = 'WriteDAC'
  [uint32]'0x00020000' = 'ReadControl'
  [uint32]'0x00010000' = 'Delete'
  [uint32]'0x00000100' = 'WriteAttributes'
  [uint32]'0x00000080' = 'ReadAttributes'
  [uint32]'0x00000040' = 'DeleteChild'
  [uint32]'0x00000020' = 'Execute/Traverse'
  [uint32]'0x00000010' = 'WriteExtendedAttributes'
  [uint32]'0x00000008' = 'ReadExtendedAttributes'
  [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
  [uint32]'0x00000002' = 'WriteData/AddFile'
  [uint32]'0x00000001' = 'ReadData/ListDirectory'
}

# Function to generate permission string from an ACL
function Get-PermissionString ($Acl) {
    $Permissions = $Acl.Access | Where-Object { $ExcludeUsers -notcontains $_.IdentityReference.Value } | ForEach-Object {
        $fileSystemRights = [uint32]$_.FileSystemRights.value__
        $username = $_.IdentityReference
        $accessControlType = $_.AccessControlType
        $permList = $accessMask.Keys |
                    Where-Object { $fileSystemRights -band $_ } |
                    ForEach-Object { $accessMask[$_] }
        "$username; $($permList -join ', '); $accessControlType"
    }
    return $Permissions -join '|'
}

# Get all directories recursively
$FolderPath = Get-ChildItem -Directory -Path $TargetFolderPath -Recurse -Force
$Report = @()

# Iterate over each directory and analyze permissions
foreach ($Folder in $FolderPath) {
    $Acl = Get-Acl -Path $Folder.FullName
    $Permissions = Get-PermissionString $Acl

    $ParentAcl = Get-Acl -Path $Folder.Parent.FullName
    $ParentPermissions = Get-PermissionString $ParentAcl

    # If permissions are different from parent or not inherited from parent, add to report
    if (($Permissions -ne $ParentPermissions) -or $Acl.AreAccessRulesProtected) {
        $Report += New-Object PSObject -Property @{
            Folder = $Folder.FullName
            Permissions = $Permissions
        }
    }
}

# Export report to CSV
$Report | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
