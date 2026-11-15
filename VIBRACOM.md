# vibracom-agentes

**Based on agentes.chat by Codari Global, LLC.** Fork mantido pela Listralize para a equipe da vibracom, sob a mesma licença (AGPL-3.0-only, ver `LICENSE` e `NOTICE`). Código-fonte desta versão modificada: https://github.com/listralize/vibracom-agentes (é o `SOURCE_URL` da instância). "agentes.chat" é marca da Codari Global, LLC (ver `TRADEMARKS.md`); este fork não é um produto da Codari.

## O que muda em relação ao upstream

Todas as mudanças são opcionais por variável de ambiente; sem elas, o comportamento é o do upstream.

| Variável | Para quê |
| --- | --- |
| `FRAME_ANCESTORS` | Origens que podem mostrar o app em iframe (o menu "Agentes" do vibracom-sistema). Troca `frame-ancestors 'none'` por `'self'` + essas origens e tira o `X-Frame-Options: DENY`. |
| `SESSION_COOKIE_SAMESITE` | `lax` (padrão). `none` (Secure + Partitioned) só se o sistema que embute estiver em outro site (outro domínio registrável). |
| `VIBRACOM_SSO_SECRET`, `VIBRACOM_SSO_ORG_ID` | Login entregue pelo vibracom-sistema: `GET /api/auth/vibracom-sso?t=<JWT HS256>` (iss `vibracom-sistema`, aud = origem do `PUBLIC_URL`, `email`, `name`, vida máx. 120 s, `jti` de uso único). Cria a pessoa se preciso (sem senha), adiciona como membro do workspace e abre a sessão. Nunca dá papel de dono/admin. |
| `MCP_CALLER_IDENTITY` (upstream) | O fork acrescenta o claim `email` à declaração assinada, para o servidor MCP do vibracom-sistema responder com as permissões (RLS) da própria pessoa. |

Arquivos: `apps/server/src/vibracom-sso.ts`, `apps/server/src/app.ts` (`appCsp`), `apps/server/src/auth.ts`, `packages/engine/src/connectors/mcp.ts`, `packages/config/src/schema.ts`, testes em `apps/server/test/vibracom-sso.test.ts`.

## Publicação (Coolify)

`docker-compose.vibracom.yml`: Postgres 18 + pgvector com volume persistente e o app construído a partir deste repositório. Telemetria desligada (`TELEMETRY=off`), feedback não é enviado ao upstream (`FEEDBACK_RELAY=false`), cadastro fechado (`ALLOW_SIGNUP=false`). Variáveis obrigatórias no Coolify: `POSTGRES_PASSWORD`, `PUBLIC_URL`, `AGENTES_SECRET`.

## Backup

The `backup` service in `docker-compose.vibracom.yml` runs once at start and then every 24 h:
`pg_dump -Fc` of the database and a tar of the uploaded files, kept 14 days in the `vibracom-agentes-backups`
volume on the server. Restore a dump (with the app stopped):

```sh
docker exec -i <postgres-container> pg_restore -U agentes -d agentes --clean --if-exists < agentes-AAAAMMDD-HHMM.dump
```

## Shortcuts from vibracom-sistema

- `GET /api/auth/vibracom-status` (Bearer: HS256 token with `purpose: "status"`, signed with `VIBRACOM_SSO_SECRET`):
  whether a model key is set, and the workspace's agents. No key, no person data.
- `/org/<org>/dm/agent/<agent>?texto=…` opens the DM with that question in the composer, for the person to send.
