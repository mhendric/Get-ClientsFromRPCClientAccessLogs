<#PSScriptInfo

.VERSION 1.0.0

.GUID 11dcc13e-2949-4481-aec5-9658d0fefaae

.AUTHOR Mike Hendrickson

.COMPANYNAME Microsoft Corporation

.COPYRIGHT (C) Microsoft Corporation. All rights reserved.

#>

<# 
.Synopsis
 Parses the RPC Client Access logs of one or more Exchange 2010+ servers looking for a specific client operation
 type, and exports the found results to .CSV. Performs the search of each target computer in parallel. The target
 computers perform their log search locally, and then return the results to the machine where the script is executed
 from. This approach conserves memory on the script computer, and significantly speeds up the collection time.

.PARAMETERS
 -Computers: Defines the list of computers to search the RPC Client Access logs on. Computers should share the same log path. 
 -RPCLogPath: The local RPC Client Access log path on each target computer to search. Uses the default Exchang 2013/2016 path by default.
 -MaxAgeInDays: The maximum number of days to search within each log. Defaults to 7.
 -DesiredFields: The columns to retrieve from found results within each log. Defaults to "client-software", "client-software-version","user-email".
 -Operation: The operation type to look for in each log. Defaults to OwnerLogon.
 -ClientSoftware: If used, specifies a specific 'client-software' type to look for in the logs. If empty, gets all 'client-software' types.
 -Exclusions: A hashtable of column name/value pairs that should be excluded from results. Excluded HealthMailbox's by default.
 -GroupResultsByDesiredFields: Whether the results should be grouped by the types defined in DesiredFields. Defaults to $true
 -GroupResultsByTargetComputer: Whether the results should be grouped by the computer they were retrieved from. Defaults to $false

.EXAMPLE 1: Parses the RPC Client Access logs on two Exchange 2013/2016 servers
PS> .\Get-ClientsFromRPCClientAccessLogs.ps1 -Computers ex2013srv1,ex2016srv2 -Verbose

.EXAMPLE 2: Parses the RPC Client Access logs on two Exchange 2013/2016 servers for connect operations and gets the IP of each client
PS> .\Get-ClientsFromRPCClientAccessLogs.ps1 -Computers ex2013srv1,ex2016srv2 -Operation "Connect" -DesiredFields @("client-software", "client-software-version","user-email","client-ip") -Verbose  

.EXAMPLE 3: Parses the RPC Client Access logs on two Exchange 2013/2016 servers, and groups the results by each target computer.
PS> .\Get-ClientsFromRPCClientAccessLogs.ps1 -Computers ex2013srv1,ex2016srv2 -GroupResultsByTargetComputer $true

.EXAMPLE 4: Parses the RPC Client Access log on an Exchange 2010 server
PS> .\Get-ClientsFromRPCClientAccessLogs.ps1 -Computers ex2010srv3 -RPCLogPath "C:\Program Files\Microsoft\Exchange Server\V14\Logging\RPC Client Access"

#>

[CmdletBinding()]
param
(
    [string[]]
    $Computers,

    [string]
    $RPCLogPath = "C:\Program Files\Microsoft\Exchange Server\V15\Logging\RPC Client Access",

    [uint64]
    $MaxAgeInDays = 7,

    [string[]]
    $DesiredFields = @("client-software", "client-software-version","user-email"),

    [string]
    $Operation = "OwnerLogon",

    [string]
    $ClientSoftware = "",

    [Hashtable]
    $Exclusions = @{"user-email" = "HealthMailbox*"},

    [Boolean]
    $GroupResultsByDesiredFields = $true,

    [Boolean]
    $GroupResultsByTargetComputer = $false
)

function ValidateParameters
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [string[]]
        $Computers,

        [string]
        $RPCLogPath,

        [uint64]
        $MaxAgeInDays,

        [string[]]
        $DesiredFields,

        [string]
        $Operation
    )

    [bool]$isValid = $true

    if ($Computers -eq $null -or $Computers.Count -eq 0)
    {
        Write-Error "Computers parameter must not be null or empty"
        $isValid = $false
    }
    
    if (([string]::IsNullOrEmpty($RPCLogPath)) -eq $true)
    {
        Write-Error "RPCLogPath parameter must not be null or empty"
        $isValid = $false
    }

    if ($MaxAgeInDays -le 0)
    {
        Write-Error "MaxAgeInDays must be greater than 0"
        $isValid = $false
    }

    if ($DesiredFields -eq $null -or $DesiredFields.Count -eq 0)
    {
        Write-Error "DesiredFields parameter must not be null or empty"
        $isValid = $false
    }

    if (([string]::IsNullOrEmpty($Operation)) -eq $true)
    {
        Write-Error "Operation parameter must not be null or empty"
        $isValid = $false
    }

    return $isValid
}

function GetClientTypes
{
    [CmdletBinding()]
    param
    (
        [string]
        $RPCLogPath,

        [uint64]
        $MaxAgeInDays,

        [string[]]
        $DesiredFields,

        [string]
        $Operation,

        [string]
        $ClientSoftware,

        [Hashtable]
        $Exclusions,

        [Boolean]
        $GroupResultsByDesiredFields
    )

    [Object[]]$connectionList = @()

    if ((Test-Path -Path $RPCLogPath) -eq $true)
    {
        [DateTime]$oldestDate = [DateTime]::Now.AddDays($MaxAgeInDays * -1)

        $files = $null
        $files = Get-ChildItem -LiteralPath "$($RPCLogPath)" -ErrorAction SilentlyContinue | where {$_.LastWriteTime -gt $oldestDate -and $_.Name -like "*.log" -and $_.Length -gt 0}

        if ($files -ne $null)
        {
            foreach ($file in $files)
            {
                $csvColumnsLine = $null
                $csvColumns = $null
                $csvColumnsLine = Get-Content -Path $file.FullName -TotalCount 10 | where {$_.StartsWith("#Fields")}

                if ($csvColumnsLine -ne $null)
                {
                    $csvColumns = $csvColumnsLine.Replace("#Fields: ", "").Split(',')
                }

                if ($csvColumns -ne $null)
                {
                    $csv = Import-Csv -Header $csvColumns -Path $file.FullName
                }        

                if ($csv -eq $null)
                {
                    continue
                }

                $clientMatches = $csv | where {$_."operation" -like $Operation}

                if (([string]::IsNullOrEmpty($ClientName)) -eq $false)
                {
                    $clientMatches = $clientMatches | where {$_."client-software" -like $ClientSoftware}
                }

                if ($Exclusions -ne $null -and $Exclusions.Keys.Count -gt 0)
                {
                    foreach ($key in $Exclusions.Keys)
                    {
                        $clientMatches = $clientMatches | where {$_.$key -notlike $Exclusions[$key]}
                    }
                }

                if ($clientMatches -ne $null)
                {
                    foreach ($match in $clientMatches)
                    {
                        $connectionList += ($match | Select-Object -Property $DesiredFields)
                    }
                }
            }
        }
    }

    if ($connectionList.Count -gt 0 -and $GroupResultsByDesiredFields -eq $true)
    {
        $grouped = $connectionList | Group-Object -Property $DesiredFields

        if ($grouped.GetType().Name -like "GroupInfo")
        {
            $groupedResults = $grouped.Group[0]
        }
        else #This is an array of GroupInfo objects
        {
            $groupedResults = for ($i = 0; $i -lt $grouped.Count; $i++) {$grouped[$i].Group[0]}
        }

        return $groupedResults
    }
    else
    {
        return $connectionList
    }
}

####################################################################################################
# Script starts here
####################################################################################################

if ((ValidateParameters -Computers $Computers -RPCLogPath $RPCLogPath -MaxAgeInDays $MaxAgeInDays -DesiredFields $DesiredFields -Operation $Operation) -eq $false)
{
    Write-Error "One or more script parameters failed validation. Exiting script."
    return
}

Write-Host "$([DateTime]::Now) Beginning remote RPC Client Access log search"

Write-Verbose "$([DateTime]::Now) Sending remote collection job"

$jobs = Invoke-Command -ComputerName $Computers -ScriptBlock ${function:GetClientTypes} -ArgumentList $RPCLogPath,$MaxAgeInDays,$DesiredFields,$Operation,$ClientSoftware,$Exclusions,$GroupResultsByDesiredFields -AsJob

Write-Verbose "$([DateTime]::Now) Waiting for job results"

$silencer = Wait-Job $jobs
$results = Receive-Job $jobs

if ($results -ne $null)
{
    if ($GroupResultsByTargetComputer -eq $true)
    {
        $DesiredFields += "PSComputerName"
    }

    if ($GroupResultsByDesiredFields -eq $true)
    {
        Write-Verbose "$([DateTime]::Now) Grouping results"

        $grouped = $results | Select-Object -Property $DesiredFields | Group-Object -Property $DesiredFields

        if ($grouped.GetType().Name -like "GroupInfo")
        {
            $groupedResults = $grouped.Group[0]
        }
        else #This is an array of GroupInfo objects
        {
            $groupedResults = for ($i = 0; $i -lt $grouped.Count; $i++) {$grouped[$i].Group[0]}
        }

        Write-Verbose "$([DateTime]::Now) Exporting results to csv"

        $groupedResults | Export-Csv ClientTypeDiscovery.csv -NoTypeInformation
        $groupedResults
    }
    else
    {        
        $results = $results | Select-Object -Property $DesiredFields

        Write-Verbose "$([DateTime]::Now) Exporting results to csv"

        $results | Export-Csv ClientTypeDiscovery.csv -NoTypeInformation
        $results
    }
}
else
{
    Write-Verbose "$([DateTime]::Now) Log search returned 0 results."
}

Write-Host "`n$([DateTime]::Now) Finished RPC Client Access log search"
