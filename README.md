# iouring-setup-guard

**ES:** Guard userspace (API / dry-run) de allowlist sobre flags de
`io_uring_setup` (SQPOLL, IOPOLL, NO_MMAP, …) + catálogo residual CVE↔superficie
citado desde iouring-lab RATIONALE.

**EN:** Userspace allowlist for `io_uring_setup` flags plus a residual
CVE↔surface catalog grounded in iouring-lab RATIONALE.

Los filtros cBPF task-level (#38) **no** cubren setup flags (~12% de CVEs
io_uring 2024-02..2026-09 según RATIONALE).

## Medición (caja)

```bash
cargo run --bin iouring-setup-guard -- measure --runs 50
# deny_list_block=50/50 clean_setup=allow

cargo run --bin iouring-setup-guard -- check --flag-name IORING_SETUP_SQPOLL
# decision=deny

cargo run --bin iouring-setup-guard -- catalog
# entries=12
```

SQPOLL con `--call-kernel` puede devolver EPERM sin privilegios: se reporta,
no se saltea en silencio.

## Límites

| Qué | Dónde |
|-----|--------|
| Allowlist + catálogo + setup limpio | caja |
| LD_PRELOAD interposición real | fuera del MVP de hoy (API lista) |
| Filtrado kernel de setup flags | no existe aún (pedido en RATIONALE) |

## Fuentes leídas

- https://github.com/gvozdetsky/iouring-lab/blob/main/profile/RATIONALE.md
- man `io_uring_setup_flags(7)`
- OCI runtime-spec#1323

License: Apache-2.0
