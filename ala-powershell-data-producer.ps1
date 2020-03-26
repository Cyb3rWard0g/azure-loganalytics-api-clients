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
                              \/           \/    \/      V0.0.1

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
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing -Verbose
    return $response.StatusCode

}

$APILimitBytes = 30 * 1mb

foreach ($dataset in $all_files)
{
    $total_file_size = (get-item -Path $dataset).Length
    $json_records = @()
    $json_current_size = 0

    # Read each JSON object from file
    foreach($line in [System.IO.File]::ReadLines($dataset))
    {
        Start-Sleep -s 0.1
        $lineSize = [System.Text.ASCIIEncoding]::UTF8.GetByteCount($line)
        $json_current_size += ($lineSize + 1 )

        Write-Progress -Activity "Processing files" -status "Processing $dataset" -percentComplete ($json_current_size / $total_file_size * 100)

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

        # Maximum of 30MB per post to Azure Monitor Data Collector API
        if ($json_current_size -lt $APILimitBytes)
        {
            $json_records += $message
        }
        else
        {
            # Submit the data to the API endpoint
            $json_records = $json_records | ConvertTo-Json
            Post-LogAnalyticsData -customerId $WorkspaceId -sharedKey $WorkspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json_records)) -logType $logType
            $json_records = @()
            $json_current_size = 0
        }

        # if you get to read the whole file without reaching the 30MB limit per post
        if ($json_current_size -eq $total_file_size)
        {
            # Submit the data to the API endpoint
            $json_records = $json_records | ConvertTo-Json
            Post-LogAnalyticsData -customerId $WorkspaceId -sharedKey $WorkspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json_records)) -logType $logType   
        }
    }
}