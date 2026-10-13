# Routes

TanStack Start uses **file-based routing**: every `.tsx` file in this directory is a
route, and `src/routeTree.gen.ts` is generated from them — never edit it by hand.
`__root.tsx` is the app shell and must keep its `<Outlet />`.

## This app's routes

| File                             | URL                    | Screen                                            |
| -------------------------------- | ---------------------- | ------------------------------------------------- |
| `index.tsx`                      | `/`                    | Dashboard                                         |
| `honeypots.tsx`                  | `/honeypots`           | Honeypot fleet                                    |
| `sessions/index.tsx`             | `/sessions`            | Attack sessions + campaigns                       |
| `sessions/$sessionId.tsx`        | `/sessions/:sessionId` | Session investigation, AI analysis, analyst notes |
| `logs.tsx`                       | `/logs`                | Log Explorer (`?event=<id>` opens one event)      |
| `analysis.tsx`                   | `/analysis`            | AI analysis history                               |
| `mitre.tsx`                      | `/mitre`               | MITRE ATT&CK matrix                               |
| `threat-intel.tsx`               | `/threat-intel`        | Indicators, export, VirusTotal                    |
| `attackers/$ip.tsx`              | `/attackers/:ip`       | Attacker profile + third-party reputation         |
| `reports.tsx`                    | `/reports`             | Threat reports                                    |
| `evaluation/index.tsx`           | `/evaluation`          | Realism evaluation runs                           |
| `evaluation/$runId.tsx`          | `/evaluation/:runId`   | One run, findings, remediation                    |
| `evaluation/compare.tsx`         | `/evaluation/compare`  | Run-versus-run comparison                         |
| `settings.tsx`                   | `/settings`            | Data source and service health                    |
| `sign-in.$.tsx`, `sign-up.$.tsx` | `/sign-in`, `/sign-up` | Clerk (splat routes)                              |

## Conventions

A dynamic segment is a bare `$` (`sessions/$sessionId.tsx`), a splat is `$.tsx` read via
the `_splat` param, and a layout route renders its children through `<Outlet />`. Do not
create `src/pages/` or `app/layout.tsx` — those are Next.js / Remix conventions.
