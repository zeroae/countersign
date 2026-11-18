param([string]$Action, [string]$Name, [string]$Certificate, [ValidateSet("p256","p384","rsa")][string]$Algorithm = "p256")
$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^CountersignCI-[0-9a-f]{32}$') { throw "Invalid fixture key name" }
if ($Action -eq 'generate') {
    $options = [System.Security.Cryptography.CngKeyCreationParameters]::new()
    $options.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
    $options.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing
    $alg = switch ($Algorithm) {
        p256 { [System.Security.Cryptography.CngAlgorithm]::ECDsaP256 }
        p384 { [System.Security.Cryptography.CngAlgorithm]::ECDsaP384 }
        rsa {
            $size = [System.Security.Cryptography.CngProperty]::new("Length",[BitConverter]::GetBytes(2048),[System.Security.Cryptography.CngPropertyOptions]::None)
            $options.Parameters.Add($size)
            [System.Security.Cryptography.CngAlgorithm]::Rsa
        }
    }
    $key = [System.Security.Cryptography.CngKey]::Create($alg, $Name, $options)
    $signer = if ($Algorithm -eq "rsa") { [System.Security.Cryptography.RSACng]::new($key) }
              else { [System.Security.Cryptography.ECDsaCng]::new($key) }
    [Convert]::ToBase64String($signer.ExportSubjectPublicKeyInfo())
} elseif ($Action -eq 'install') {
    $key = [System.Security.Cryptography.CngKey]::Open($Name)
    $signer = if ($Algorithm -eq "rsa") { [System.Security.Cryptography.RSACng]::new($key) }
              else { [System.Security.Cryptography.ECDsaCng]::new($key) }
    $leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Certificate)
    $cert = if ($Algorithm -eq "rsa") {
        [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($leaf,$signer)
    } else {
        [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($leaf,$signer)
    }
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My','CurrentUser')
    $store.Open('ReadWrite')
    $store.Add($cert)
    $store.Close()
} else { throw "Invalid fixture action" }
