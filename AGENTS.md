# Repository scope

This repository owns the shared WordPress integration policy between Microsoft
Entra ID, OpenID Connect Generic Client and Municipio user groups.

- Keep tenant IDs, client IDs, client secrets, group IDs and site-specific role
  mappings out of this repository.
- Keep protocol handling in `daggerhart/openid-connect-generic`; this plugin
  owns policy and Municipio integration only.
- Treat authentication and network changes as fail-closed and add regression
  coverage in `tests/run.php`.
