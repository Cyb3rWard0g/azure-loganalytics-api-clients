# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: GPL-3.0

# Reference: https://docs.microsoft.com/en-us/azure/azure-monitor/platform/data-collector-api#powershell-sample

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$WorkspaceId,

    [Parameter(Mandatory=$true)]
    [string]$WorkspaceSharedKey,

    [Parameter(Mandatory=$true)]
    [string]$LogType,

    [Parameter(Mandatory=$false)]
    [string]$TimeStampField,

    [Parameter(Mandatory=$true)]
    [ValidateScript({
        foreach ($f in $_)
        {
            if( -Not ($f | Test-Path) ){
                throw "File or folder does not exist"
            }
        }
        return $true
    })]
    [string[]]$FilePath,
    
    [Parameter(Mandatory=$false)]
    [switch]$PackMessage

)

If ($PSBoundParameters['Debug']) {
    $DebugPreference = 'Continue'
}


@("
   _____  .____       _____    ________          __          
  /  _  \ |    |     /  _  \   \______ \ _____ _/  |______   
 /  /_\  \|    |    /  /_\  \   |    |  \\__  \\   __\__  \  
/    |    \    |___/    |    \  |    `   \/ __ \|  |  / __ \_
\____|__  /_______ \____|__  / /_______  (____  /__| (____  /
        \/        \/       \/          \/     \/          \/ 
__________                   .___                            
\______   \_______  ____   __| _/_ __   ____  ___________    
 |     ___/\_  __ \/  _ \ / __ |  |  \_/ ___\/ __ \_  __ \   
 |    |     |  | \(  <_> ) /_/ |  |  /\  \__\  ___/|  | \/   
 |____|     |__|   \____/\____ |____/  \___  >___  >__|      
                              \/           \/    \/      V0.0.2
Creator: Roberto Rodriguez @Cyb3rWard0g
License: GPL-3.0
 
")

# Aggregate files from input paths
$all_files = @()
foreach ($file in $FilePath){
    if ((Get-Item $file) -is [system.io.fileinfo]){
        $all_files += (Resolve-Path -Path $file)
    }
    elseif ((Get-Item $file) -is [System.IO.DirectoryInfo]){
        $folderfiles = Get-ChildItem -Path $file -Recurse -Include *.json
        $all_files += $folderfiles
    }
}

# Create the function to create the authorization signature
Function Build-Signature ($customerId, $sharedkey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedkey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}


# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedkey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedkey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource

    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    if ($TimeStampField.length -gt 0)
    {
        $headers = @{
            "Authorization" = $signature;
            "Log-Type" = $logType;
            "x-ms-date" = $rfc1123date;
            "time-generated-field"=$TimeStampField;
        }
    }
    else {
         $headers = @{
            "Authorization" = $signature;
            "Log-Type" = $logType;
            "x-ms-date" = $rfc1123date;
        }
    }
    write-verbose "Total Bytes Sent: $contentLength bytes"
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing -Verbose
    return $response.StatusCode

}

$APILimitBytes = 5 * 1mb
foreach ($dataset in $all_files)
{
    $total_file_size = (get-item -Path $dataset).Length
    $json_records = New-Object System.Collections.ArrayList
    $json_current_size = 0
    $event_count = 0

    Write-Host "Dataset: $dataset"
    Write-Host "Total File Size: $total_file_size bytes"

    # Create ReadLines Iterator and get total number of lines
    $readLineIterator = [System.IO.File]::ReadLines($dataset)
    $numberOfLines = [Linq.Enumerable]::Count($readLineIterator)
    
    # Read each JSON object from file
    foreach($line in $readLineIterator)
    {
        if ($PackMessage)
        {
            $message = @{
                "message" = $line
            }
        }
        else
        {
            $message = $line | ConvertFrom-Json
        }
        
        # Increase event number
        $event_count += 1

        # Update progress bar with current event count
        Write-Progress -Activity "Processing files" -status "Processing $dataset" -percentComplete ($event_count / $numberOfLines * 100)

        write-debug "############ Event $event_count ###############"
        # Read one line and get its size in bytes
        $message_size = ([System.Text.Encoding]::UTF8.GetBytes(($line | ConvertFrom-Json | convertto-json -Compress))).Length
        Write-Debug "Reading One Message: $message_size bytes"

        $new_body_size = ([System.Text.Encoding]::UTF8.GetBytes(($json_records + $message | ConvertTo-Json -Compress))).Length
        write-debug "Compressed Message Array: $new_body_size"

        # Procesing current bytes from file
        $json_current_size += $message_size
        write-debug "Processing the following bytes so far: $json_current_size"

        # Maximum of 30 MB per post to Azure Monitor Data Collector API but splitting it in 5MB chunks.
        if ($new_body_size -lt $APILimitBytes -and $event_count -ne $numberOfLines)
        {
            $json_records.Add($message) > $null
        }
        else
        {
            if ($event_count -eq $numberOfLines)
            {
                $json_records.Add($message) > $null
                If ($PSBoundParameters['Debug'])
                {
                    $message_size = ([System.Text.Encoding]::UTF8.GetBytes(($message | convertto-json -Compress))).Length
                    Write-Debug "Appending last $message_size bytes"
                }
            }
            $json_records = $json_records | ConvertTo-Json -Compress
            # Send JSON Blob to Azure Sentinel Log Analytics Workspace
            Post-LogAnalyticsData -customerId $WorkspaceId -sharedKey $WorkspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json_records)) -logType $logType
            if ($event_count -ne $numberOfLines)
            {
                $json_records = New-Object System.Collections.ArrayList
                $json_records.Add($message) > $null
                If ($PSBoundParameters['Debug'])
                {
                    $message_size = ([System.Text.Encoding]::UTF8.GetBytes(($message | convertto-json -Compress))).Length
                    Write-Debug "Carrying over $message_size bytes"
                }
            }
        }
    }
    Write-Host "Finished Processing $dataset"
    Write-Host "Total Events Processed $event_count"
    Write-Host "Total Bytes Processed: $json_current_size bytes"
}