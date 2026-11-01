# Known pitfalls when upgrading .NET

Check this list first when the build breaks or before deploying. It covers problems seen in real
upgrades and common traps; it is not exhaustive. The official lists are the source of truth:

- .NET 10: https://learn.microsoft.com/dotnet/core/compatibility/10.0
- .NET 9: https://learn.microsoft.com/dotnet/core/compatibility/9.0
- .NET 8: https://learn.microsoft.com/dotnet/core/compatibility/8.0
- EF Core: https://learn.microsoft.com/ef/core/what-is-new/ (see "Breaking changes" per version)
- Support policy: https://dotnet.microsoft.com/platform/support/policy/dotnet-core

## Upgrading to .NET 10 (from 8 or 9)

### OpenAPI / Swagger

- `Microsoft.AspNetCore.OpenApi` 10 depends on **Microsoft.OpenApi 2.x**. Swashbuckle 6/7/8/9 are built on
  1.x and fail at build or at runtime. Upgrade `Swashbuckle.AspNetCore` to **10.x** (or drop it if only
  `MapOpenApi()` is used).
- Namespace change: `using Microsoft.OpenApi.Models;` → `using Microsoft.OpenApi;`.
- Security requirements reference schemes with `new OpenApiSecuritySchemeReference("Bearer", document)`
  instead of `new OpenApiSecurityScheme { Reference = new OpenApiReference { ... } }`. In Swashbuckle 10,
  `AddSecurityRequirement` takes a `Func<OpenApiDocument, OpenApiSecurityRequirement>`.
- In custom schema/operation/document filters (and **their tests**):
  - schemas are `IOpenApiSchema`; `Properties` is `IDictionary<string, IOpenApiSchema>`;
  - a reference is a separate type, `OpenApiSchemaReference`, instead of `schema.Reference != null`;
  - `schema.Type` is the flags enum `JsonSchemaType` (`JsonSchemaType.String`), not the string `"string"`;
  - `Properties`, `Required` and other collections can be `null`. Null-check them.
- `.WithOpenApi()` on minimal endpoints is obsolete (`ASPDEPR002`); remove it, metadata is generated anyway.

### C# 14 (default language version of .NET 10)

- **Overload resolution / first-class span conversions** can turn previously fine calls into `CS0121`
  (ambiguous call) or bind them to a different overload. Typical case: types with many implicit conversions,
  e.g. StackExchange.Redis `RedisValue` passed to `JsonSerializer.Deserialize(...)`. Fix with an explicit
  cast (`(string)value`), not by pinning an older `LangVersion`.
- `array.Contains(x)` inside **expression trees** can now bind to `MemoryExtensions.Contains(ReadOnlySpan)`.
  EF Core 10 handles it, but older LINQ providers or custom expression visitors may throw at runtime.
  Test LINQ queries that use `Contains` on arrays.
- `field` is a contextual keyword inside property accessors: a member called `field` used there must be
  written `this.field` or `@field`. `extension` is also contextual now.

### Containers

- `mcr.microsoft.com/dotnet/*:10.0` default tags are **Ubuntu 24.04 (noble)**, not Debian. `apt` package
  names may differ, and the image already has a `ubuntu` user with **UID 1000**: `useradd -u 1000` fails.
  Use the built-in non-root `app` user (UID 1654, `USER $APP_UID`) or another UID.
- Need Debian? Use an explicit variant tag if one exists for the target, or keep Alpine/Chiseled if the
  project already used them.

### EF Core 10

- After bumping, run `dotnet ef migrations has-pending-model-changes` (update the `dotnet-ef` tool to the
  new major first). It should report no changes. If it does, stop: something in the conventions changed
  and needs a deliberate migration.
- Keep all `Microsoft.EntityFrameworkCore.*` packages and the provider (Npgsql, Pomelo, SqlServer) on
  the same major. Npgsql's provider versions follow EF's major.

### SDK / build

- SDK 9+ audits **transitive** packages by default (`NuGetAuditMode=all`). With `TreatWarningsAsErrors`,
  new `NU1901`-`NU1904` errors appear: fix the vulnerable package, do not disable the audit.
- New analyzers in the target SDK can add warnings; with `TreatWarningsAsErrors` they become errors.
  Fix or suppress individually with a reason.
- `Polly.Extensions.Http` is deprecated; the replacement is `Microsoft.Extensions.Http.Resilience`.
  If the old package is referenced but unused, just remove it.

## Coming from .NET 6 or 7 (to 8+)

- **Containers listen on port 8080** by default since .NET 8 (`ASPNETCORE_HTTP_PORTS`), not 80. Update
  `EXPOSE`, health checks, Kubernetes `containerPort`/probes and compose port mappings, or set
  `ASPNETCORE_HTTP_PORTS=80` explicitly.
- Images ship a non-root `app` user (`$APP_UID`); good time to stop running as root.
- `BinaryFormatter` always throws starting in .NET 9. Replace it (System.Text.Json, protobuf, etc.);
  the compatibility package `System.Runtime.Serialization.Formatters` exists but is unsupported.
- `Microsoft.AspNetCore.Authentication.JwtBearer` 8+ uses `JsonWebTokenHandler`: code that inspects
  `SecurityToken` as `JwtSecurityToken` in events gets a `JsonWebToken` instead.

## Coming from .NET Core 3.1 / .NET 5

- `Startup.cs` + `Program.cs` still work on .NET 10; moving to minimal hosting is optional. Do not mix it
  into a security upgrade.
- `Newtonsoft.Json` is still allowed, but versions < 13.0.1 are vulnerable (GHSA-5crp-9r3c-p9vr).
- Many `Microsoft.AspNetCore.*` 2.x packages (for example `Microsoft.AspNetCore.Http`) were folded into
  the shared framework: remove the `PackageReference` instead of upgrading it.

## .NET Framework

Not an automatic upgrade. 4.6.2 to 4.8.1 are still supported as a Windows component, so the security
priority is the vulnerable packages, not the framework. Moving to modern .NET is a project of its own;
tools that help: .NET Upgrade Assistant and GitHub Copilot app modernization. Ask the user.

## Packages whose license changed (do not bump the major without asking)

| Package | Commercial from | Note |
|---|---|---|
| MediatR | 13.0 | 12.x stays Apache-2.0 and works on .NET 10 |
| AutoMapper | 15.0 | 14.x stays MIT |
| MassTransit | 9.0 | 8.x stays Apache-2.0 |
| FluentAssertions | 8.0 | 7.x stays Apache-2.0; AwesomeAssertions is a community fork |

If one of these has a vulnerability only fixed in the commercial major, stop and tell the user.
