# dotnet-eol-guard

**.NET 8 y .NET 9 pierden soporte el 10 de noviembre de 2026.** Desde ese día dejan de recibir parches de
seguridad. `dotnet-eol-guard` encuentra todos los lugares donde un repositorio depende de una versión de .NET
sin soporte o de un paquete NuGet vulnerable, y le da a cualquier agente de IA un playbook probado para
arreglarlo y demostrar que quedó arreglado.

[English](README.md)

## Qué revisa

| Dónde | Qué |
|---|---|
| `*.csproj`, `Directory.Build.props` | `TargetFramework(s)` en versiones vencidas o por vencer (.NET Core 1.0 → .NET 9, .NET Framework viejo) |
| `global.json` | El SDK fijado |
| `Dockerfile`, compose, YAML de Kubernetes, devcontainer | Tags de `mcr.microsoft.com/dotnet/*` y las imágenes retiradas `microsoft/dotnet` de Docker Hub |
| GitHub Actions, Azure Pipelines, cualquier YAML | `setup-dotnet`, `UseDotNet@2`, variables `DOTNET_VERSION` |
| `PackageReference` / `Directory.Packages.props` | ASP.NET Core, EF Core, `Microsoft.Extensions.*` y proveedores de EF atados a un runtime viejo |
| NuGet (directos **y transitivos**) | Vulnerabilidades conocidas (GitHub Advisory Database vía `dotnet list package --vulnerable`) y paquetes deprecados |
| Versiones de patch fijadas | Tags como `aspnet:10.0.13`, `RuntimeFrameworkVersion`, el SDK de `global.json`: se marcan si un patch posterior corrigió CVEs **del runtime mismo**, que ninguna auditoría de NuGet ve |
| Esta máquina (`--installed`) | Runtimes instalados sin soporte o sin los parches de seguridad |
| CVEs puntuales (`--cve`) | Responde "¿me afecta la CVE-X?": si la corrige un release de .NET y qué está expuesto en el repo |

Las fechas de soporte se leen en vivo del
[`releases-index.json`](https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json)
oficial de Microsoft, así que la herramienta sigue siendo correcta cuando venza la próxima versión. Sin red
usa una copia incluida.

## Dos partes, cualquier IA

1. **Escáner** (`skills/dotnet-eol-guard/scripts/eol-guard.cs`): un solo archivo C#, sin IA y sin
   dependencias. Lee el repo, nunca lo modifica, y produce un reporte Markdown o JSON con un código de
   salida que sirve en CI.
2. **Playbook** (`skills/dotnet-eol-guard/SKILL.md`): instrucciones paso a paso para cualquier agente:
   escanear → planear → línea base de build y tests → actualizar en un orden seguro → corregir cambios que
   rompen → tests → re-escanear → reportar. Incluye una lista de trampas reales
   ([`references/breaking-changes.md`](skills/dotnet-eol-guard/references/breaking-changes.md)): OpenAPI 2.x
   y Swashbuckle 10, ambigüedades de sobrecarga de C# 14, imágenes de .NET 10 basadas en Ubuntu, el puerto
   8080, y paquetes que pasaron a licencia comercial (MediatR, AutoMapper, MassTransit, FluentAssertions).

`SKILL.md` usa el formato abierto [Agent Skills](https://agentskills.io): funciona con Claude Code, OpenAI
Codex, GitHub Copilot, Cursor y otros. Cualquier asistente que pueda leer un archivo puede seguirlo.

## Inicio rápido

Requiere el [SDK de .NET 10](https://dotnet.microsoft.com/download), que de todas formas hace falta para
migrar.

### Solo escanear

```bash
git clone https://github.com/GDriem/dotnet-eol-guard
cd dotnet-eol-guard/skills/dotnet-eol-guard/scripts
dotnet run eol-guard.cs -- --path /ruta/a/tu/repo
```

Córrelo desde la carpeta `scripts`: dentro de un repo cuyo `global.json` fija un SDK viejo, `dotnet` elige
ese SDK y no puede ejecutar apps de un solo archivo. Las opciones están en el [README en inglés](README.md#just-scan)
y en `dotnet run eol-guard.cs -- --help`.

### Arreglarlo con un agente

Instala el skill y pídele a tu agente: *"Saca este repo de las versiones de .NET sin soporte y corrige los
paquetes vulnerables usando el skill dotnet-eol-guard."*

| Agente | Instalación |
|---|---|
| Claude Code | `/plugin marketplace add GDriem/dotnet-eol-guard` y luego `/plugin install dotnet-eol-guard@dotnet-eol-guard`, o copiar `skills/dotnet-eol-guard` a `~/.claude/skills/` |
| GitHub Copilot (VS Code / Visual Studio) | copiar `skills/dotnet-eol-guard` a `.github/skills/` del repo o a `~/.copilot/skills/` |
| OpenAI Codex | copiar `skills/dotnet-eol-guard` a `.agents/skills/` del repo, y `codex/agents/*.toml` a `.codex/agents/` |
| Varios agentes en un repo | `.agents/skills/dotnet-eol-guard/` lo leen muchos |
| Cualquier otro | agregar [`adapters/AGENTS.md.snippet`](adapters/AGENTS.md.snippet) a tu `AGENTS.md`, o pegar [`adapters/prompt.md`](adapters/prompt.md) en el chat |

**Delegación para ahorrar tokens.** En repos grandes, el playbook reparte el trabajo pesado entre sub-agentes,
cada uno con el modelo más barato que alcance para su tarea. El escaneo y la verificación van en un modelo tipo
Haiku y la actualización mecánica de cada unidad en uno tipo Sonnet. El modelo más fuerte solo recibe los errores
de build que resistieron dos intentos. El orquestador solo ve resúmenes cortos, nunca el JSON del escáner ni los
logs de build. El plugin de Claude Code los trae listos en `agents/` (`eol-scanner`, `eol-upgrader`,
`eol-build-fixer`, `eol-verifier`). Si instalas copiando, copia también `agents/*.md` a `~/.claude/agents/` o
`.claude/agents/`. Para **OpenAI Codex**, copia `codex/agents/*.toml` a `.codex/agents/` (proyecto) o
`~/.codex/agents/` (personal). Usan `gpt-6-luna` para escanear y verificar, y `gpt-6.1-sol` para los cambios y
los errores de build. Si tu cuenta tiene otros modelos, cambia `MODELS` en `tools/gen-codex-agents.py` y
córrelo.

El playbook mantiene al agente con la rienda corta: cambios mínimos, nada de suprimir warnings en bloque, ni
apagar la auditoría de NuGet, ni saltarse tests. Además tiene que preguntar antes de migrar .NET Framework,
de subir un paquete a una versión con licencia comercial o de tocar el esquema de la base de datos.

### En CI

```yaml
- uses: actions/checkout@v4
- uses: GDriem/dotnet-eol-guard@v0.1.0
  with:
    fail-on: high      # critical | high | medium | low | none
```

El reporte queda en el resumen del job. Prográmalo también semanal: aparecen CVEs y fechas de fin de soporte
nuevas sin que cambie el código. Ejemplo completo: [`examples/github-workflow.yml`](examples/github-workflow.yml).

## Limitaciones

- Los proyectos con `packages.config` no se pueden auditar con la CLI de .NET; el reporte lo indica.
- La auditoría de NuGet necesita que `dotnet restore` funcione (acceso a feeds privados, SDK correcto).
- Los valores que vienen de propiedades de MSBuild o build args de Docker se reportan como "no verificable".
- .NET MAUI y las cargas móviles tienen su propia política de soporte; el reporte la enlaza.
- .NET Framework → .NET moderno se señala, pero nunca se automatiza.

## Licencia

[MIT](LICENSE) © Gadi Orellana
