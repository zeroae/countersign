param([string]$Addon, [string]$TestScript, [string]$Record)
$ErrorActionPreference = 'Stop'
# The caller has just created a user-scoped CNG key in its own profile.
# Give a separate disposable local user only the public test inputs.
$tag = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$name = "csci$tag"
$shared = Join-Path $env:PUBLIC $name
$secret = ConvertTo-SecureString ([Guid]::NewGuid().ToString() + 'aA7!') -AsPlainText -Force
try {
    New-Item -ItemType Directory -Path $shared | Out-Null
    Copy-Item $Addon (Join-Path $shared 'countersign.node')
    Copy-Item $TestScript (Join-Path $shared 'test.cjs')
    Copy-Item $Record (Join-Path $shared 'record.json')
    $user = New-LocalUser -Name $name -Password $secret
    $users = Get-LocalGroup -SID 'S-1-5-32-545'
    if (!(Get-LocalGroupMember -Group $users | Where-Object SID -eq $user.SID)) {
        Add-LocalGroupMember -Group $users -Member $user
    }
    $cred = [PSCredential]::new("$env:COMPUTERNAME\$name", $secret)
    Start-Service seclogon
    $flags = '"{0}\test.cjs" "{0}\countersign.node" locked "{0}\record.json"' -f $shared
    $p = Start-Process (Get-Command node).Source -ArgumentList $flags -WorkingDirectory $shared -Credential $cred -LoadUserProfile -PassThru
    if (!$p.WaitForExit(40000)) { $p.Kill(); throw 'Cold login exceeded deadline' }
    if ($p.ExitCode -ne 0) { throw 'Different Windows user failed cold access assertions' }
} finally {
    if (Get-LocalUser $name -ErrorAction SilentlyContinue) { Remove-LocalUser $name }
    if (Test-Path $shared) { Remove-Item -LiteralPath $shared -Recurse }
}
