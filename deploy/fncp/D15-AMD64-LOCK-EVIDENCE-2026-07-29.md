# D15 — Native AMD64 child-manifest lock evidence

Date: 29 July 2026
Decision: **HOLD / NO-GO**

Every public image index used by the Option C source and scanner path was
resolved read-only through Docker Hub. The exact Linux/AMD64 child-manifest
digests are now recorded beside the existing Linux/ARM64 digests in
`image-security.lock.json`.

| Locked reference | Linux/AMD64 child manifest |
|---|---|
| Dockerfile frontend 1.4 | `sha256:ad87fb03593d1b71f9a1cfc1406c4aafcb253b1dabebf569768d6e6166836f34` |
| Node 22 Alpine | `sha256:b74031e546d7f4faf561d797ac1b76beccac856a042815ca77db4fd047581605` |
| Node 24 Alpine | `sha256:4ba75f835bb8802193e4c114572113d4b26f95f6f094f4b5229d2a77773e0afc` |
| PostgreSQL 17 Alpine | `sha256:af194ccf3e2d7fe367012c7b88ce8b816c5c889b18a5b316799a1f0d7eac746a` |
| Clojure Temurin 17 tools-deps | `sha256:fc9298c9e6625f26529490c14a52d14727f0383545a40e97382506bac4becf18` |
| Amazon Corretto 17 Alpine | `sha256:67546ab389ec51aa479112c861f995b23e88cdffb84708c1f739859eb7c8c5ce` |
| Alpine 3.24 | `sha256:79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f` |
| Node 24 slim | `sha256:d45d78e7929b46875bbd4e29bea672d5bc48186c6c3588306521c815e78352d6` |
| nginx 1.30.4 Alpine 3.24 slim | `sha256:45c3810793fe3e982fb614c67e1b696816aff3ec742620e1ef7cd9d3184185ef` |
| Syft 1.49.0 | `sha256:9a9f85314017f1ea798fb012edfa7fe9259923910f82c8d4bc983ab5c765e60b` |
| Grype 0.116.0 | `sha256:3d08845e24eba657b8ea9bd28344a5a4e9dcd772818062a6522bf30137928616` |

The lock validator now rejects a missing or malformed AMD64 digest for the
Dockerfile frontend, any base-image use or either scanner.

This is prerequisite provenance, not AMD64 execution evidence. No GitHub
workflow was dispatched, no registry login occurred, no image was published or
signed, and no cloud infrastructure was created. The separate native Linux
AMD64 eight-image build/SBOM/scan run remains required.
