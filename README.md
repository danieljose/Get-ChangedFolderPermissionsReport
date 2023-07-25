# Get-ChangedFolderPermissionsReport.ps1

## Description

This PowerShell script generates a report of directories that have non-inherited or modified permissions in comparison to their parent directories. It is especially useful for auditing security settings on a Windows filesystem.

## Parameters

- `-StartFolder` (_mandatory_): The path of the folder where the script starts the analysis.
- `-DestinationFile` (_mandatory_): The full path of the output file where the script writes the results.
- `-ExcludeUsers` (_optional_): A list of user or group names to exclude from the analysis. Input should be a comma-separated string of user/group names (e.g. `"NT AUTHORITY\SYSTEM,BUILTIN\Administrators"`).
- `-Help`: Shows help information.

## Usage

To execute the script, navigate to its directory in a PowerShell terminal and run:

```
./Get-ChangedFolderPermissionsReport.ps1 -StartFolder "C:\folder_to_analyze" -DestinationFile "C:\path\to\output.txt"
```

To exclude specific users from the analysis, use the -ExcludeUsers parameter:

```
./Get-ChangedFolderPermissionsReport.ps1 -StartFolder "C:\folder_to_analyze" -DestinationFile "C:\path\to\output.txt" -ExcludeUsers "NT AUTHORITY\SYSTEM,BUILTIN\Administrators"
```
