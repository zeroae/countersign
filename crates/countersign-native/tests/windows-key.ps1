param([string]$Action, [string]$Name, [string]$Certificate)
$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^CountersignCI-[0-9a-f]{32}$') { throw "Invalid fixture key name" }
if ($Action -eq 'generate') {
    $options = [System.Security.Cryptography.CngKeyCreationParameters]::new()
    $options.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
    $options.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing
    $key = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::ECDsaP256, $Name, $options)
    $ec = [System.Security.Cryptography.ECDsaCng]::new($key)
    [Convert]::ToBase64String($ec.ExportSubjectPublicKeyInfo())
} elseif ($Action -eq 'install') {
    $key = [System.Security.Cryptography.CngKey]::Open($Name)
    $ec = [System.Security.Cryptography.ECDsaCng]::new($key)
    $leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Certificate)
    $cert = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($leaf,$ec)
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My','CurrentUser')
    $store.Open('ReadWrite')
    $store.Add($cert)
    $store.Close()
} else { throw "Invalid fixture action" }
