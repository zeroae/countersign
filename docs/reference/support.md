# Tested platforms

If you are evaluating Countersign for a desktop fleet, start with the provider and processor your users actually have. The runs below exercised implementation revision `fbb5aa7`. They distinguish a native TLS test, loading the packaged application, and driving an approval all the way to a website.

## Native identity and desktop packages

| Desktop | Processor | Website signing and pairing | Packaged Electron |
|---|---|---|---|
| Ubuntu 24.04 | x64 | [SoftHSM2 and encrypted GNOME Keyring](https://github.com/zeroae/countersign/actions/runs/44195966477/job/134438940967) | [AppImage and deb build, bundled addon load](https://github.com/zeroae/countersign/actions/runs/44195966471/job/134437705939) |
| Ubuntu 24.04 | ARM64 | [SoftHSM2 and encrypted GNOME Keyring](https://github.com/zeroae/countersign/actions/runs/44195966477/job/134438941006) | [AppImage and deb build, bundled addon load](https://github.com/zeroae/countersign/actions/runs/44195966471/job/134437705811) |
| Windows Server 2025 | x64 | [Current-user certificate store and CNG](https://github.com/zeroae/countersign/actions/runs/44195966477/job/134438940945) | [NSIS installer build, bundled addon load](https://github.com/zeroae/countersign/actions/runs/44195966471/job/134437706078) |
| Windows 11 | ARM64 | [Current-user certificate store and CNG](https://github.com/zeroae/countersign/actions/runs/44195966477/job/134438940499) | [NSIS installer build, bundled addon load](https://github.com/zeroae/countersign/actions/runs/44195966471/job/134437705940) |
| macOS 15 | Intel | [Keychain and Security.framework](https://github.com/zeroae/countersign/actions/runs/44195966477/job/134438941420) | [pkg build, bundled addon load](https://github.com/zeroae/countersign/actions/runs/44195966471/job/134437706082) |
| macOS 26 | Apple silicon | [Keychain and Security.framework](https://github.com/zeroae/countersign/actions/runs/44195966477/job/134438940871) | [pkg build, bundled addon load](https://github.com/zeroae/countersign/actions/runs/44195966471/job/134437705910) |

Each native job loads the production addon, exercises selection with two and three eligible identities, and signs real TLS 1.2 and 1.3 handshakes. The combinations cover ECDSA P-256/P-384, RSA-PSS with SHA-256/384/512 and, on TLS 1.2, RSA PKCS#1 with those hash functions. The harness checks that the peer received the selected leaf. The distribution jobs build unsigned installers and use the matching Electron runtime to load the bundled addon. [Native TLS harness](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/crates/countersign-native/tests/native_mtls.rs)

On Linux the website key lives in the PKCS#11 provider. The Companion creates a separate non-extractable NSS pairing key and keeps its unlock secret in the encrypted login collection. CI restarted the credential service and exercised cold access, a locked collection and retirement on both hosted Linux architectures. Other Secret Service implementations and physical tokens need their own qualification. [Linux keyring test](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/crates/countersign-native/tests/linux-keyring.py)

## End-to-end and deployment evidence

| Environment | Observed result |
|---|---|
| Hosted Linux x64 | The packaged Companion approved the last of two and three same-name identities. curl ran as a separate user, the mTLS site observed the chosen fingerprint, and revocation denied the next request. The same job exercised Linux shared and sidecar workers and lease cutoff. [End-to-end job](https://github.com/zeroae/countersign/actions/runs/44195966499/job/134437689804) |
| Local Linux ARM64 | The packaged Companion paired through Chromium with two Integrators. The user selected the second of two identically named certificates. A curl container reached the mTLS site and its peer fingerprint matched the selected identity. The wildcard and alternate-brand prompts were opened and denied. [Walkthrough and observed fingerprint](../try.md#choose-a-certificate-and-verify-it) |
| Local Linux ARM64 conda installation | A locally built and installed Companion completed the two-certificate mTLS flow. The recipe currently builds for Linux. [Recorded run](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/docs/specs/2026-11-17-countersign-design.md#qualification-evidence) |
| Shared Linux Gateway and issuer | Test workers with separate grant identities ran concurrently. Local CA and ACM-PCA API fixtures exercised exact-host leaf issuance. The SDK fixture checks signed API requests and a TLS handshake with the resulting leaf. [Shared runtime tests](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/crates/countersign-gateway/tests/runtime.py) · [Issuer tests](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/crates/countersign-gateway/src/shared_issuer.rs) |

Full graphical pairing-to-website runs on Windows and macOS, physical smartcards and their PIN dialogs, other Linux keyrings, live AWS Private CA or ZAE-ZCM, production shared infrastructure and external protected sites remain unqualified. Signed Windows releases and macOS notarization also await credentials and a release run.
