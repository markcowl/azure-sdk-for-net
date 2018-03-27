$errorStream = New-Object -TypeName "System.Text.StringBuilder";
$outputStream = New-Object -TypeName "System.Text.StringBuilder";


function Clear-OutputStreams {
    $errorStream.Clear() | Out-Null
    $outputStream.Clear() | Out-Null
}

function Write-InfoLog {
    param(
        [string] $msg,
        [switch] $logToConsole,
        [switch] $logToFile
    )
    if(![string]::IsNullOrEmpty($msg) -and $logToFile)
    {
        $outputStream.Append("$msg`n") | Out-Null
    }
    if($logToConsole)
    {
        Write-Host $msg
    }
}

function Write-ErrorLog {
    param(
        [string] $msg,
        [switch] $logToConsole,
        [switch] $logToFile
    )
    if(![string]::IsNullOrEmpty($msg) -and $logToFile)
    {
        $errorStream.Append("$msg`n") | Out-Null
    }
    if($logToConsole)
    {
        Write-Error $msg
    }
}

function launchProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string] $command, 
        [string] $args)
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $command
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    
    if(![string]::IsNullOrEmpty($args))
    {
        $pinfo.Arguments = $args
    }
    
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    Write-InfoLog $stdout -logToConsole
    Write-ErrorLog $stderr
    if($p.ExitCode -ne 0)
    {
        throw [System.Exception] "Command $cmd $args returned $p.ExitCode"
    }
}

function Get-AutoRestHelp {
    Write-InfoLog "Fetching AutoRest help" -logToConsole
    launchProcess "cmd.exe" "/c autorest.cmd --help"
}

function Install-AutoRest {
    param(
        [Parameter(Mandatory = $true)]
        $AutoRestVersion
    )
    
    Write-InfoLog "Installing AutoRest version: $AutoRestVersion" -logToConsole
    
    Try {
        launchProcess "cmd.exe" "/c npm.cmd install -g autorest@$AutoRestVersion"
    }
    Catch [System.Exception] {
        Write-ErrorLog $_.Exception.ToString()
        throw [System.Exception] "AutoRest Installation failed"
    }
    Write-InfoLog "AutoRest installed successfully." -logToConsole
}

function Start-CodeGeneration {
param(
    [Parameter(Mandatory = $true)]
    [string] $SpecsRepoFork,
    [Parameter(Mandatory = $true)]
    [string] $SpecsRepoBranch,
    [Parameter(Mandatory = $true)]
    [string] $SpecsRepoName,
    [Parameter(Mandatory = $true, HelpMessage ="Please provide an output directory for the generated code")]
    [string] $SdkDirectory,
    [Parameter(Mandatory = $true, HelpMessage ="Please provide a version for the AutoRest release")]
    [string] $AutoRestVersion
    )
    
    $configFile="https://github.com/$SpecsRepoFork/$SpecsRepoName/blob/$SpecsRepoBranch/specification/$ResourceProvider/readme.md" 
    Write-InfoLog "Generating CSharp code" -logToConsole
    $cmd = "cmd.exe"
    $args = "/c autorest.cmd $configFile --csharp --csharp-sdks-folder=$SdkDirectory --version=$AutoRestVersion --reflect-api-versions"
    
    Write-InfoLog "Executing AutoRest command" -logToFile
    Write-InfoLog "$cmd $args" -logToFile

    Try {
        launchProcess $cmd $args
    }
    Catch [System.Exception] {
        Write-ErrorLog $_.Exception.ToString()
        throw [System.Exception] "AutoRest code generation for $configFile failed. Please try again"
    }
    
    Try {
        Start-MetadataGeneration -AutoRestVersion $AutoRestVersion -SpecsRepoFork $SpecsRepoFork -SpecsRepoBranch $SpecsRepoBranch
    }
    Catch [System.Exception] {
        Write-ErrorLog $_.Exception.ToString()
        throw [System.Exception] "Metadata generation for $configFile failed. Please try again"
    }
}

function Start-MetadataGeneration {
    param(

        [Parameter(Mandatory = $true)]
        [string] $AutoRestVersion,
        [Parameter(Mandatory = $true)]
        [string] $SpecsRepoFork,
        [Parameter(Mandatory = $true)]
        [string] $SpecsRepoBranch
    )
    
    Write-InfoLog $([DateTime]::UtcNow.ToString('u').Replace('Z',' UTC')) -logToFile

    Write-InfoLog "" -logToFile
    Write-InfoLog "1) azure-rest-api-specs repository information" -logToFile
    Write-InfoLog "GitHub fork: $SpecsRepoFork" -logToFile
    Write-InfoLog "Branch:      $SpecsRepoBranch" -logToFile
    
    Try
    {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $op = (Invoke-RestMethod "https://api.github.com/repos/$($SpecsRepoFork)/azure-rest-api-specs/branches/$($SpecsRepoBranch)").commit.sha | Out-String
        Write-InfoLog "Commit:      $op" -logToFile
    }
    Catch [System.Exception]
    {
        Write-ErrorLog $_.Exception.ToString()
        throw $_
    }

    Write-InfoLog "" -logToFile
    Write-InfoLog "2) AutoRest information" -logToFile
    Write-InfoLog "Requested version: $AutoRestVersion" -logToFile
    
    Try
    {
        $op = $((npm list -g autorest) | Out-String).Replace("`n", " ").Replace("`r"," ").Trim()
        Write-InfoLog "Bootstrapper version:    $op" -logToFile
        Write-InfoLog "`n" -logToFile
    }
    Catch{}
    Try
    {
        $op = (autorest --list-installed | Where {$_ -like "*Latest Core Installed*"}).Split()[-1] | Out-String
        $op = $op.Replace("`n", " ").Replace("`r"," ").Trim()
        Write-InfoLog "Latest installed version:    $op" -logToFile
    }
    Catch{}
    Try
    {
        $op = (autorest --list-installed | Where {$_ -like "*@microsoft.azure/autorest-core*"} | Select -Last 1).Split('|')[3] | Out-String
        $op = $op.Replace("`n", " ").Replace("`r"," ").Trim()
        Write-InfoLog "Latest installed version:    $op" -logToFile
    }
    Catch{}
}

function Get-ErrorStream {
    $errorStream.ToString()
}

function Get-OutputStream {
    $outputStream.ToString()
}


export-modulemember -function Get-AutoRestHelp
export-modulemember -function Install-AutoRest
export-modulemember -function Start-CodeGeneration
export-modulemember -function Get-ErrorStream
export-modulemember -function Get-OutputStream
export-modulemember -function Write-InfoLog
export-modulemember -function Write-ErrorLog
export-modulemember -function Clear-OutputStreams