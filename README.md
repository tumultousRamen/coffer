# coffer

Credentials vault microservice — Byteport work trial.

A Go/gRPC service that stores customer credentials for external storage providers (S3, Dropbox, Google Drive, Box) and delivers them to transfer workers at transfer time. Designed for modular, replaceable deployment so Byteport can extract it into their production system.

- [PRD](docs/PRD.md)
- [ADRs](docs/adr/)
