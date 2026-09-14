# Azure confidential-container evidence fixtures

Public sample files, copied unmodified. Used to test offline verification against real Azure evidence.

| file | from | commit |
|---|---|---|
| sidecar-snp_report.bin | microsoft/confidential-sidecar-containers `pkg/attest/test_data/snp_report.bin` | 0c126b0a543762eda8f459f9fd5abfb90981fbb4 |
| sidecar-uvm_security_policy.base64 | same repo, `pkg/attest/test_data/uvm_security_policy.base64` | same |
| sidecar-uvm_host_amd_certificate.json | same repo, `pkg/attest/test_data/uvm_host_amd_certificate.json` | same |
| sidecar-body.uvm_reference_info.bin | same repo, `pkg/attest/test_data/body.uvm_reference_info.bin` | same |
| kms-snp.json | microsoft/azure-privacy-sandbox-kms `test/attestation-samples/snp.json` (a complete `/attest/combined` response) | a004656fa5722accfeb708b09d17a5d0e0234f9c |

Licenses: both repositories are MIT (Copyright (c) Microsoft Corporation). Fetched 2026-09-14.

SHA-256:
```
15ace5202a1ad77a085d3418ada3cd7ab183b00c81d060108a5e514451ae72f6  sidecar-body.uvm_reference_info.bin
8aa044299042322a6b8027c1445cbdd691c9312db75c2da1ad7d95d328750925  sidecar-snp_report.bin
3c6609a55055db43f41778e3d6b75397c2181a54ca44695a4cc7c5499bf12831  sidecar-uvm_host_amd_certificate.json
f052433bc8844ef8dde0288ae9764256f66cb869ea72cd4c1b58ff347a6eb120  sidecar-uvm_security_policy.base64
de855f7c14cd49e044a3980d99592f33ad3006b87864714bca8058d6f74feaa5  kms-snp.json
```
