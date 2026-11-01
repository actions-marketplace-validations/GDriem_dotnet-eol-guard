#!/usr/bin/env dotnet
#:property PublishAot=false
#:property Nullable=enable

// dotnet-eol-guard: finds end-of-life .NET runtimes, SDKs, container images and CI pins in a repository,
// plus NuGet packages with known vulnerabilities or deprecations. It never edits files.
//
// Usage:  dotnet run eol-guard.cs -- --path <repo> [options]
// Exit:   0 = nothing at or above --fail-on, 1 = findings at or above it, 2 = usage or runtime error.

using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

const string ToolVersion = "0.1.0";

Options opts;
try { opts = Options.Parse(args); }
catch (ArgumentException ex)
{
    Console.Error.WriteLine($"error: {ex.Message}\n");
    Console.Error.WriteLine(Options.Usage);
    return 2;
}
if (opts.Help) { Console.WriteLine(Options.Usage); return 0; }

var root = Path.GetFullPath(opts.Path);
if (!Directory.Exists(root))
{
    Console.Error.WriteLine($"error: directory not found: {root}");
    return 2;
}

var asOf = opts.AsOf ?? DateOnly.FromDateTime(DateTime.Now);
var lifecycle = await Lifecycle.LoadAsync(opts.Offline);

Channel? target;
if (opts.Target is { } requested)
{
    target = lifecycle.Find(requested);
    if (target is null)
    {
        Console.Error.WriteLine($"error: unknown .NET channel '{requested}'");
        return 2;
    }
}
else
{
    target = lifecycle.RecommendedLts(asOf, opts.WarnDays);
}

var scanner = new Scanner(root, asOf, opts.WarnDays, lifecycle, target, opts.Cves);
scanner.ScanFiles();
if (opts.Installed) scanner.ScanInstalledRuntimes();
scanner.CheckCves();
if (!opts.NoPackages) scanner.AuditPackages(restore: !opts.NoRestore, log: Console.Error);

var report = new Report(root, asOf, lifecycle, target, scanner.Findings, opts.FailOn, ToolVersion);
var output = opts.Format == "json" ? report.ToJson() : report.ToMarkdown();
if (opts.Out is { } outFile)
{
    File.WriteAllText(outFile, output);
    Console.Error.WriteLine($"report written to {outFile}");
}
else
{
    Console.WriteLine(output);
}

return report.Failed ? 1 : 0;

// ---------------------------------------------------------------------------------------------------------------

enum Severity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }

record Finding(
    string Category,
    Severity Severity,
    string File,
    int Line,
    string Subject,
    string Current,
    string Message,
    string? Recommendation,
    string? Url = null);

record Release(Version Runtime, DateOnly Date, string[] Cves, string[] Sdks);

record Channel(string Version, string ReleaseType, string Phase, DateOnly? Eol, string? LatestRuntime, string? LatestSdk)
{
    public bool IsPrerelease => Phase is "preview" or "go-live" or "rc";
    public int Major => int.Parse(Version.Split('.')[0], CultureInfo.InvariantCulture);
    public string Label => $".NET {Version} ({ReleaseType.ToUpperInvariant()})";
}

sealed class Options
{
    public string Path { get; private set; } = ".";
    public string Format { get; private set; } = "md";
    public string? Out { get; private set; }
    public Severity? FailOn { get; private set; } = Severity.High;
    public int WarnDays { get; private set; } = 180;
    public string? Target { get; private set; }
    public DateOnly? AsOf { get; private set; }
    public bool Offline { get; private set; }
    public bool NoPackages { get; private set; }
    public bool NoRestore { get; private set; }
    public bool Installed { get; private set; }
    public List<string> Cves { get; } = [];
    public bool Help { get; private set; }

    public const string Usage = """
        dotnet-eol-guard - audit a .NET repository for end-of-life runtimes and vulnerable packages

        Usage: dotnet run eol-guard.cs -- --path <repo> [options]

          --path <dir>           Repository to scan (default: current directory)
          --format md|json       Output format (default: md)
          --out <file>           Write the report to a file instead of stdout
          --fail-on <level>      critical|high|medium|low|none (default: high)
          --warn-days <n>        Flag channels that lose support within n days (default: 180)
          --target <x.y>         Channel to recommend (default: newest supported LTS)
          --as-of <yyyy-MM-dd>   Evaluate support dates as of this day (default: today)
          --offline              Use the built-in lifecycle snapshot instead of releases-index.json
          --no-packages          Skip the NuGet vulnerability/deprecation audit
          --no-restore           Do not run 'dotnet restore' before auditing packages
          --installed            Also check the .NET runtimes installed on this machine (servers, IIS, VMs)
          --cve <id>[,<id>...]   Say whether these CVEs are .NET runtime fixes and what in the repo is exposed
          -h, --help             Show this help
        """;

    public static Options Parse(string[] args)
    {
        var o = new Options();
        for (var i = 0; i < args.Length; i++)
        {
            string Next() => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"{args[i]} needs a value");
            switch (args[i])
            {
                case "--path": o.Path = Next(); break;
                case "--format":
                    o.Format = Next().ToLowerInvariant();
                    if (o.Format is not ("md" or "json")) throw new ArgumentException("--format must be md or json");
                    break;
                case "--out": o.Out = Next(); break;
                case "--fail-on":
                    var level = Next().ToLowerInvariant();
                    o.FailOn = level == "none" ? null
                        : Enum.TryParse<Severity>(level, ignoreCase: true, out var s) && s != Severity.Info ? s
                        : throw new ArgumentException("--fail-on must be critical, high, medium, low or none");
                    break;
                case "--warn-days":
                    o.WarnDays = int.TryParse(Next(), out var d) && d >= 0 ? d : throw new ArgumentException("--warn-days must be a non-negative integer");
                    break;
                case "--target": o.Target = Next(); break;
                case "--as-of":
                    o.AsOf = DateOnly.TryParseExact(Next(), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var a)
                        ? a : throw new ArgumentException("--as-of must be yyyy-MM-dd");
                    break;
                case "--offline": o.Offline = true; break;
                case "--no-packages": o.NoPackages = true; break;
                case "--no-restore": o.NoRestore = true; break;
                case "--installed": o.Installed = true; break;
                case "--cve":
                    o.Cves.AddRange(Next().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(c => c.ToUpperInvariant()));
                    break;
                case "-h" or "--help": o.Help = true; break;
                default: throw new ArgumentException($"unknown option {args[i]}");
            }
        }
        return o;
    }
}

sealed class Lifecycle
{
    static readonly string[] IndexUrls =
    [
        "https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json",
        "https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/releases-index.json",
    ];

    // Fallback when the network is unavailable. Snapshot of releases-index.json taken 2026-10-31.
    const string SnapshotDate = "2026-10-31";
    static readonly Channel[] Snapshot =
    [
        new("11.0", "sts", "go-live", null, "11.0.0-rc.3.26522.148", "11.0.100-rc.3.26522.148"),
        new("10.0", "lts", "active", new DateOnly(2028, 11, 14), "10.0.14", "10.0.403"),
        new("9.0", "sts", "maintenance", new DateOnly(2026, 11, 10), "9.0.22", "9.0.320"),
        new("8.0", "lts", "maintenance", new DateOnly(2026, 11, 10), "8.0.33", "8.0.427"),
        new("7.0", "sts", "eol", new DateOnly(2024, 5, 14), "7.0.20", "7.0.410"),
        new("6.0", "lts", "eol", new DateOnly(2024, 11, 12), "6.0.36", "6.0.428"),
        new("5.0", "sts", "eol", new DateOnly(2022, 5, 10), "5.0.17", "5.0.408"),
        new("3.1", "lts", "eol", new DateOnly(2022, 12, 13), "3.1.32", "3.1.426"),
        new("3.0", "sts", "eol", new DateOnly(2020, 3, 3), "3.0.3", "3.0.103"),
        new("2.2", "sts", "eol", new DateOnly(2019, 12, 23), "2.2.8", "2.2.207"),
        new("2.1", "lts", "eol", new DateOnly(2021, 8, 21), "2.1.30", "2.1.818"),
        new("2.0", "sts", "eol", new DateOnly(2018, 10, 1), "2.0.9", "2.1.202"),
        new("1.1", "lts", "eol", new DateOnly(2019, 6, 27), "1.1.13", "1.1.14"),
        new("1.0", "lts", "eol", new DateOnly(2019, 6, 27), "1.0.16", "1.1.14"),
    ];

    public IReadOnlyList<Channel> Channels { get; }
    public string Source { get; }
    readonly bool live;
    public bool Live => live;
    readonly Dictionary<string, IReadOnlyList<Release>?> releases = [];

    Lifecycle(IReadOnlyList<Channel> channels, string source, bool live) => (Channels, Source, this.live) = (channels, source, live);

    // Patch-level CVEs need each channel's releases.json; null when offline or unavailable.
    public IReadOnlyList<Release>? Releases(string channel)
    {
        if (!live) return null;
        if (releases.TryGetValue(channel, out var cached)) return cached;
        IReadOnlyList<Release>? list = null;
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("dotnet-eol-guard");
            var json = JsonNode.Parse(http.GetStringAsync($"https://builds.dotnet.microsoft.com/dotnet/release-metadata/{channel}/releases.json").GetAwaiter().GetResult());
            list = json?["releases"]?.AsArray()
                .Where(r => r is not null)
                .Select(r => (Node: r!, Runtime: (string?)r!["runtime"]?["version"] ?? (string?)r["release-version"]))
                .Where(x => x.Runtime is not null && !x.Runtime.Contains('-') && Version.TryParse(x.Runtime, out _))
                .Select(x => new Release(
                    Version.Parse(x.Runtime!),
                    DateOnly.TryParse((string?)x.Node["release-date"], CultureInfo.InvariantCulture, out var d) ? d : default,
                    x.Node["cve-list"]?.AsArray().Select(c => (string?)c?["cve-id"]).OfType<string>().ToArray() ?? [],
                    (x.Node["sdks"]?.AsArray().Select(sd => (string?)sd?["version"]) ?? [(string?)x.Node["sdk"]?["version"]]).OfType<string>().ToArray()))
                .ToList();
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException)
        {
        }
        releases[channel] = list;
        return list;
    }

    public static async Task<Lifecycle> LoadAsync(bool offline)
    {
        if (!offline)
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("dotnet-eol-guard");
            foreach (var url in IndexUrls)
            {
                try
                {
                    var json = JsonNode.Parse(await http.GetStringAsync(url));
                    var channels = json?["releases-index"]?.AsArray()
                        .Select(n => new Channel(
                            (string)n!["channel-version"]!,
                            (string?)n["release-type"] ?? "unknown",
                            (string?)n["support-phase"] ?? "unknown",
                            n["eol-date"] is { } e && DateOnly.TryParse((string?)e, CultureInfo.InvariantCulture, out var d) ? d : null,
                            (string?)n["latest-runtime"],
                            (string?)n["latest-sdk"]))
                        .ToList();
                    if (channels is { Count: > 0 }) return new Lifecycle(channels, $"live ({url})", live: true);
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException)
                {
                    // try the next mirror, then fall back to the snapshot
                }
            }
        }
        return new Lifecycle(Snapshot, $"offline snapshot from {SnapshotDate}", live: false);
    }

    public Channel? Find(string version) => Channels.FirstOrDefault(c => c.Version == version);

    public Channel? RecommendedLts(DateOnly asOf, int warnDays) => Channels
        .Where(c => c.ReleaseType == "lts" && !c.IsPrerelease && c.Phase != "eol"
                    && (c.Eol is null || c.Eol > asOf.AddDays(warnDays)))
        .OrderByDescending(c => Version.Parse(c.Version))
        .FirstOrDefault();
}

sealed partial class Scanner(string root, DateOnly asOf, int warnDays, Lifecycle lifecycle, Channel? target, IReadOnlyList<string> requestedCves)
{
    readonly List<(string Where, HashSet<string> Cves)> patchExposure = [];

    static readonly HashSet<string> SkippedDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git", "bin", "obj", "node_modules", ".vs", ".idea", "packages", "TestResults", ".terraform",
    };

    static readonly string[] NotRuntimeAligned =
    [
        "Microsoft.Extensions.AI", "Microsoft.Extensions.Azure", "Microsoft.Extensions.ServiceDiscovery",
        "Microsoft.Extensions.VectorData", "Microsoft.AspNetCore.Mvc.Versioning", "Microsoft.AspNetCore.OData",
        "Microsoft.AspNetCore.SpaServices",
    ];

    static readonly string[] RuntimeAlignedExact =
    [
        "System.Text.Json", "System.Net.Http.Json", "Microsoft.Data.Sqlite",
        "Npgsql.EntityFrameworkCore.PostgreSQL", "Pomelo.EntityFrameworkCore.MySql",
    ];

    readonly Dictionary<string, Finding> findings = [];
    readonly List<string> projects = [];

    public IEnumerable<Finding> Findings => findings.Values;

    string TargetText => target is null ? "a supported .NET version" : $"{target.Label}";

    void Add(Finding f) => findings.TryAdd($"{f.Category}|{f.File}|{f.Line}|{f.Subject}|{f.Current}", f);

    string Rel(string path) => Path.GetRelativePath(root, path).Replace('\\', '/');

    static int LineOf(string text, int index)
    {
        var line = 1;
        for (var i = 0; i < index && i < text.Length; i++) if (text[i] == '\n') line++;
        return line;
    }

    public void ScanFiles()
    {
        foreach (var file in Walk(root))
        {
            var name = Path.GetFileName(file);
            var ext = Path.GetExtension(file).ToLowerInvariant();
            string text;
            try
            {
                if (new FileInfo(file).Length > 2_000_000) continue;
                text = File.ReadAllText(file);
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            var isProject = ext is ".csproj" or ".fsproj" or ".vbproj";
            var isMsbuild = isProject || ext is ".props" or ".targets";
            var isDocker = name.StartsWith("Dockerfile", StringComparison.OrdinalIgnoreCase)
                           || ext == ".dockerfile" || name.Equals("Containerfile", StringComparison.OrdinalIgnoreCase);
            var isYaml = ext is ".yml" or ".yaml";

            if (isProject)
            {
                projects.Add(file);
                if (File.Exists(Path.Combine(Path.GetDirectoryName(file)!, "packages.config")))
                {
                    Add(new("package-audit", Severity.Low, Rel(file), 0, "packages.config", "packages.config",
                        "Project uses packages.config; the CLI cannot audit it for vulnerable packages.",
                        "Migrate to PackageReference (Visual Studio: right-click packages.config > Migrate) and re-run."));
                }
            }
            if (isMsbuild)
            {
                ScanTargetFrameworks(file, text);
                ScanPackageReferences(file, text);
            }
            if (name.Equals("global.json", StringComparison.OrdinalIgnoreCase)) ScanGlobalJson(file, text);
            if (isDocker || isYaml || name.Equals("devcontainer.json", StringComparison.OrdinalIgnoreCase)) ScanImages(file, text);
            if (isDocker || isYaml) ScanVersionPins(file, text);
        }
    }

    static IEnumerable<string> Walk(string dir)
    {
        var stack = new Stack<string>([dir]);
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            IEnumerable<string> files, dirs;
            try
            {
                files = Directory.EnumerateFiles(current);
                dirs = Directory.EnumerateDirectories(current)
                    .Where(d => !SkippedDirs.Contains(Path.GetFileName(d)) && new DirectoryInfo(d).LinkTarget is null)
                    .ToList();
            }
            catch (UnauthorizedAccessException) { continue; }
            foreach (var f in files) yield return f;
            foreach (var d in dirs) stack.Push(d);
        }
    }

    // ---- runtime classification ----------------------------------------------------------------------------

    (Severity, string) ClassifyChannel(string version, string what)
    {
        var ch = lifecycle.Find(version);
        if (ch is null) return (Severity.Low, $"{what} targets .NET {version}, which is not in the official release index.");
        if (ch.IsPrerelease) return (Severity.Medium, $"{what} targets {ch.Label}, a prerelease ({ch.Phase}) not meant for production.");
        if (ch.Eol is { } eol && eol <= asOf)
            return (Severity.Critical, $"{what} targets {ch.Label}, out of support since {eol:yyyy-MM-dd}: it will not receive patches for this or any future vulnerability. Migrating to {TargetText} is the only fix.");
        if (ch.Eol is { } soon && soon <= asOf.AddDays(warnDays))
            return (Severity.High, $"{what} targets {ch.Label}, which loses support on {soon:yyyy-MM-dd} ({soon.DayNumber - asOf.DayNumber} days); after that it will not receive security patches. Plan the migration to {TargetText} now.");
        return (Severity.Info, $"{what} targets {ch.Label}, supported until {(ch.Eol is { } e ? e.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "a date not yet announced")}.");
    }

    static (Severity, string) ClassifyFramework(int major, int minor, int patch)
    {
        var v = major * 100 + minor * 10 + patch;
        var label = patch > 0 ? $"{major}.{minor}.{patch}" : $"{major}.{minor}";
        if (v >= 462)
            return (Severity.Low, $".NET Framework {label} is still supported as a Windows component, but it gets no new features; moving to modern .NET is a separate migration project.");
        if (v == 350)
            return (Severity.Low, ".NET Framework 3.5 SP1 is supported until 2029-01-09; plan a migration.");
        return (Severity.Critical, $".NET Framework {label} is out of support (4.5.2, 4.6 and 4.6.1 ended on 2022-04-26); upgrade to at least 4.6.2, preferably 4.8.1.");
    }

    [GeneratedRegex(@"<(?<name>[A-Za-z_][\w.-]*Framework[\w.-]*)(?:\s[^>]*)?>\s*(?<value>[^<]+?)\s*</\k<name>>")]
    private static partial Regex FrameworkElement();

    [GeneratedRegex(@"^netcoreapp(?<maj>\d+)\.(?<min>\d+)$|^net(?<maj>\d+)\.(?<min>\d+)(?<platform>-[a-z0-9.]+)?$")]
    private static partial Regex ModernTfm();

    [GeneratedRegex(@"^net(?<maj>\d)(?<min>\d)(?<pat>\d)?$|^v(?<maj>\d)\.(?<min>\d)(?:\.(?<pat>\d))?$")]
    private static partial Regex FrameworkTfm();

    [GeneratedRegex(@"^(?<maj>\d+)\.(?<min>\d+)")]
    private static partial Regex MajorMinor();

    void ScanTargetFrameworks(string file, string text)
    {
        foreach (Match m in FrameworkElement().Matches(text))
        {
            var element = m.Groups["name"].Value;
            var line = LineOf(text, m.Index);
            foreach (var raw in m.Groups["value"].Value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var tfm = raw.ToLowerInvariant();
                if (tfm.Contains("$(")) continue;

                if (element.Equals("RuntimeFrameworkVersion", StringComparison.OrdinalIgnoreCase))
                {
                    if (MajorMinor().Match(tfm) is { Success: true } rv)
                    {
                        var (sev, msg) = ClassifyChannel($"{rv.Groups["maj"].Value}.{rv.Groups["min"].Value}", "RuntimeFrameworkVersion");
                        AddRuntime(file, line, element, raw, sev, msg);
                        if (sev == Severity.Info && Version.TryParse(raw, out var pinned))
                            AddPatchFinding(file, line, element, raw, pinned, $"RuntimeFrameworkVersion {raw}",
                                "Remove the pin (the latest installed patch is used) or raise it to {0}.");
                    }
                    continue;
                }

                if (ModernTfm().Match(tfm) is { Success: true } mm && int.Parse(mm.Groups["maj"].Value, CultureInfo.InvariantCulture) is var major
                    && (major >= 5 || tfm.StartsWith("netcoreapp", StringComparison.Ordinal)))
                {
                    var (sev, msg) = ClassifyChannel($"{major}.{mm.Groups["min"].Value}", $"<{element}>");
                    if (mm.Groups["platform"].Success && mm.Groups["platform"].Value is "-android" or "-ios" or "-maccatalyst" or "-tvos" or "-macos")
                        msg += " Mobile workloads (.NET MAUI) follow their own support policy: https://dotnet.microsoft.com/platform/support/policy/maui";
                    AddRuntime(file, line, element, raw, sev, msg);
                }
                else if (FrameworkTfm().Match(tfm) is { Success: true } fm)
                {
                    var pat = fm.Groups["pat"].Success ? int.Parse(fm.Groups["pat"].Value, CultureInfo.InvariantCulture) : 0;
                    var (sev, msg) = ClassifyFramework(int.Parse(fm.Groups["maj"].Value, CultureInfo.InvariantCulture),
                        int.Parse(fm.Groups["min"].Value, CultureInfo.InvariantCulture), pat);
                    Add(new("runtime", sev, Rel(file), line, element, raw, msg,
                        sev == Severity.Info ? null : "Decide the migration with the team; tools such as the .NET Upgrade Assistant help. Not an automatic change."));
                }
            }
        }
    }

    void AddRuntime(string file, int line, string element, string raw, Severity sev, string msg) =>
        Add(new("runtime", sev, Rel(file), line, element, raw, msg,
            sev == Severity.Info ? null : $"Retarget to {TargetTfm(raw)} ({TargetText})."));

    string TargetTfm(string current)
    {
        if (target is null) return "a supported TFM";
        var dash = current.IndexOf('-', StringComparison.Ordinal);
        var suffix = dash >= 0 ? current[dash..] : "";
        return $"net{target.Version}{suffix}";
    }

    [GeneratedRegex(@"<Package(?:Reference|Version)\b(?<attrs>[^>]*)>")]
    private static partial Regex PackageElement();

    [GeneratedRegex(@"\b(?<key>Include|Update|Version|VersionOverride)\s*=\s*""(?<value>[^""]*)""")]
    private static partial Regex Attribute();

    void ScanPackageReferences(string file, string text)
    {
        foreach (Match m in PackageElement().Matches(text))
        {
            var attrs = Attribute().Matches(m.Groups["attrs"].Value)
                .ToDictionary(a => a.Groups["key"].Value, a => a.Groups["value"].Value, StringComparer.OrdinalIgnoreCase);
            var id = attrs.GetValueOrDefault("Include") ?? attrs.GetValueOrDefault("Update");
            var version = attrs.GetValueOrDefault("VersionOverride") ?? attrs.GetValueOrDefault("Version");
            if (id is null || version is null || version.Contains("$(")) continue;
            if (MajorMinor().Match(version.TrimStart('[', '(')) is not { Success: true } v) continue;
            if (CompanionMinimum(id) is { } companion && int.Parse(v.Groups["maj"].Value, CultureInfo.InvariantCulture) < companion.MinMajor)
            {
                Add(new("package-runtime", Severity.Medium, Rel(file), LineOf(text, m.Index), id, version,
                    $"{id} {version} is not compatible with {TargetText}: {companion.Reason}",
                    $"Upgrade {id} to {companion.MinMajor}.x in the same change as the TFM."));
                continue;
            }
            if (!IsRuntimeAligned(id)) continue;

            var channel = $"{v.Groups["maj"].Value}.{v.Groups["min"].Value}";
            if (lifecycle.Find(channel) is null) continue; // versioned independently of the runtime (e.g. dotnet/extensions 10.10)
            var (sev, msg) = ClassifyChannel(channel, $"Package {id} {version}");
            if (sev == Severity.Info) continue;
            msg = msg.Replace(" targets ", " belongs to ", StringComparison.Ordinal);
            var rec = target is null ? "Upgrade with the runtime." : $"Upgrade together with the TFM to the latest {target.Major}.x patch.";
            if (v.Groups["maj"].Value == "2")
                rec += " If this project still runs on .NET Framework, ASP.NET Core 2.3.x is the supported line there.";
            Add(new("package-runtime", sev, Rel(file), LineOf(text, m.Index), id, version, msg, rec));
        }
    }

    // Third-party packages that must move together with the runtime, keyed by the first target major that needs them.
    (int MinMajor, string Reason)? CompanionMinimum(string id)
    {
        if (target is null) return null;
        if (target.Major >= 10 && id.Equals("Swashbuckle.AspNetCore", StringComparison.OrdinalIgnoreCase))
            return (10, "Microsoft.AspNetCore.OpenApi 10 brings Microsoft.OpenApi 2.x, which Swashbuckle before 10 does not support.");
        return null;
    }

    static bool IsRuntimeAligned(string id)
    {
        if (NotRuntimeAligned.Any(p => id.StartsWith(p, StringComparison.OrdinalIgnoreCase))) return false;
        return id.StartsWith("Microsoft.AspNetCore.", StringComparison.OrdinalIgnoreCase)
               || id.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.OrdinalIgnoreCase)
               || id.StartsWith("Microsoft.Extensions.", StringComparison.OrdinalIgnoreCase)
               || RuntimeAlignedExact.Contains(id, StringComparer.OrdinalIgnoreCase);
    }

    [GeneratedRegex(@"^(?<maj>\d+)\.(?<min>\d+)\.(?<pat>\d+)")]
    private static partial Regex ImagePatch();

    Version? RuntimeOfSdk(string channel, string sdk) =>
        lifecycle.Releases(channel)?.FirstOrDefault(r => r.Sdks.Contains(sdk, StringComparer.OrdinalIgnoreCase))?.Runtime;

    // Flags a pinned patch that is older than releases of the same channel which shipped CVE fixes.
    void AddPatchFinding(string file, int line, string subject, string current, Version pinned, string what, string recommendation,
        Severity severity = Severity.High, string category = "runtime-patch")
    {
        var where = file.StartsWith('(') ? file : Rel(file);
        var channel = $"{pinned.Major}.{pinned.Minor}";
        var newer = lifecycle.Releases(channel)?.Where(r => r.Runtime > pinned).ToList();
        if (newer is null || newer.Count == 0) return;
        var latest = newer.Max(r => r.Runtime)!;
        var cves = newer.SelectMany(r => r.Cves).Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(c => requestedCves.Contains(c, StringComparer.OrdinalIgnoreCase)).ThenByDescending(c => c, StringComparer.Ordinal).ToList();
        patchExposure.Add((line > 0 ? $"{where}:{line} ({subject})" : $"{where} ({subject})", cves.ToHashSet(StringComparer.OrdinalIgnoreCase)));
        if (cves.Count == 0)
        {
            Add(new(category, Severity.Low, where, line, subject, current,
                $"{what} is behind the latest patch {latest} (no CVEs fixed in between).", string.Format(CultureInfo.InvariantCulture, recommendation, latest)));
            return;
        }
        var list = cves.Count <= 8 ? string.Join(", ", cves) : $"{string.Join(", ", cves.Take(8))} and {cves.Count - 8} more";
        Add(new(category, severity, where, line, subject, current,
            $"{what} is older than .NET runtime {latest}, which fixes {cves.Count} CVE(s) in the runtime itself (not NuGet): {list}.",
            string.Format(CultureInfo.InvariantCulture, recommendation, latest)));
    }

    public void CheckCves()
    {
        if (requestedCves.Count == 0) return;
        var channels = lifecycle.Channels.Where(c => c.Phase != "eol" && c.Major >= 5).ToList();
        foreach (var cve in requestedCves.Distinct())
        {
            if (!lifecycle.Live)
            {
                Add(new("cve", Severity.Low, "(query)", 0, cve, "unknown", $"{cve}: cannot be checked offline.", "Run without --offline."));
                continue;
            }
            var fixes = channels
                .Select(c => (c.Version, Fix: lifecycle.Releases(c.Version)?.Where(r => r.Cves.Contains(cve, StringComparer.OrdinalIgnoreCase)).Select(r => r.Runtime).DefaultIfEmpty().Min()))
                .Where(x => x.Fix is not null).ToList();
            if (fixes.Count == 0)
            {
                Add(new("cve", Severity.Info, "(query)", 0, cve, "not a .NET release fix",
                    $"{cve} does not appear in the release notes of any supported .NET version ({string.Join(", ", channels.Select(c => c.Version))}), so it is not fixed by a .NET runtime or SDK update. If it affects a NuGet package, the package audit lists it by its GHSA advisory; otherwise it belongs to another product (Windows, the OS, a browser...) and is fixed outside this repository.",
                    "Check the vendor advisory and patch the affected product (for Windows: Windows Update)."));
                continue;
            }
            var fixedIn = string.Join(", ", fixes.Select(f => f.Fix!.ToString()));
            var exposed = patchExposure.Where(e => e.Cves.Contains(cve)).Select(e => e.Where).ToList();
            // Out-of-support channels never get the fix: anything still running on them stays exposed.
            var unpatchable = findings.Values
                .Where(f => f.Category is "runtime" or "container" or "installed-runtime" && f.Severity == Severity.Critical && f.Message.Contains("out of support", StringComparison.Ordinal))
                .Select(f => f.Line > 0 ? $"{f.File}:{f.Line} ({f.Current})" : $"{f.File} ({f.Subject})")
                .ToList();
            var parts = new List<string>();
            if (exposed.Count > 0) parts.Add($"Behind the patch: {string.Join("; ", exposed)}.");
            if (unpatchable.Count > 0) parts.Add($"On out-of-support .NET, where Microsoft will not ship this fix: {string.Join("; ", unpatchable)}.");
            var recs = new List<string>();
            if (exposed.Count > 0) recs.Add($"Update the pinned items to the fixed patch of their channel ({fixedIn}), rebuild images with --pull and redeploy.");
            if (unpatchable.Count > 0) recs.Add($"The out-of-support items cannot be patched: migrate them to {TargetText} (this skill's upgrade workflow).");
            Add(exposed.Count + unpatchable.Count > 0
                ? new("cve", Severity.High, "(query)", 0, cve, "exposed",
                    $"{cve} is fixed in .NET runtime {fixedIn}. {string.Join(" ", parts)}",
                    string.Join(" ", recs))
                : new("cve", Severity.Info, "(query)", 0, cve, "no pinned exposure",
                    $"{cve} is fixed in .NET runtime {fixedIn}. Nothing scanned pins an older patch. Floating image tags are only fixed after a rebuild with --pull, and hosts (VMs, IIS, developer machines) need the runtime update; check them with --installed.",
                    "Rebuild and redeploy images; update runtimes on servers."));
        }
    }

    public void ScanInstalledRuntimes()
    {
        var psi = new ProcessStartInfo("dotnet", "--list-runtimes") { RedirectStandardOutput = true, RedirectStandardError = true };
        using var p = Process.Start(psi)!;
        var output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        foreach (var raw in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = raw.Split(' ', 3);
            if (parts.Length < 2 || !Version.TryParse(parts[1], out var version)) continue;
            var subject = $"{parts[0]} {parts[1]}";
            var (sev, msg) = ClassifyChannel($"{version.Major}.{version.Minor}", $"Installed runtime {subject}");
            if (sev != Severity.Info)
            {
                Add(new("installed-runtime", sev, "(this machine)", 0, subject, parts[1], msg.Replace(" targets ", " is ", StringComparison.Ordinal),
                    $"It will not receive security patches: migrate the apps that use it to {TargetText}, then uninstall it."));
                continue;
            }
            AddPatchFinding("(this machine)", 0, subject, parts[1], version, $"Installed runtime {subject}",
                "Update it (Windows Update / Microsoft Update, your package manager, or the installer from dotnet.microsoft.com) to {0} and restart the apps that use it.",
                category: "installed-runtime");
        }
    }

    void ScanGlobalJson(string file, string text)
    {
        JsonNode? json;
        try { json = JsonNode.Parse(text, documentOptions: new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true }); }
        catch (JsonException) { return; }
        if ((string?)json?["sdk"]?["version"] is not { } sdk || MajorMinor().Match(sdk) is not { Success: true } v) return;

        var (sev, msg) = ClassifyChannel($"{v.Groups["maj"].Value}.{v.Groups["min"].Value}", "global.json SDK");
        var rollForward = (string?)json["sdk"]?["rollForward"];
        if (rollForward is not null) msg += $" rollForward: {rollForward}.";
        var idx = text.IndexOf("\"version\"", StringComparison.Ordinal);
        // Without rollForward "disable" the pin is a minimum: the newest installed SDK of the band/channel is used.
        if (sev == Severity.Info && string.Equals(rollForward, "disable", StringComparison.OrdinalIgnoreCase))
        {
            var runtime = RuntimeOfSdk($"{v.Groups["maj"].Value}.{v.Groups["min"].Value}", sdk);
            if (runtime is not null)
                AddPatchFinding(file, idx >= 0 ? LineOf(text, idx) : 1, "sdk.version", sdk, runtime, $"SDK {sdk} (bundles runtime {runtime})",
                    "Install the latest SDK of the channel and update the pin; self-contained apps embed the runtime of the SDK that published them. Latest runtime: {0}.",
                    Severity.Medium);
        }
        Add(new("sdk", sev, Rel(file), idx >= 0 ? LineOf(text, idx) : 1, "sdk.version", sdk, msg,
            sev == Severity.Info || target is null ? null : $"Pin the {target.Major} SDK (latest: {target.LatestSdk}), e.g. \"version\": \"{target.LatestSdk}\", \"rollForward\": \"latestFeature\"."));
    }

    [GeneratedRegex(@"mcr\.microsoft\.com/dotnet/(?:core/|nightly/)?(?<repo>sdk|aspnet|runtime-deps|runtime)(?::(?<tag>[\w.${}-]+))?")]
    private static partial Regex McrImage();

    [GeneratedRegex(@"(?<![\w./-])microsoft/(?<repo>dotnet|aspnetcore-build|aspnetcore)(?::(?<tag>[\w.${}-]+))?")]
    private static partial Regex LegacyHubImage();

    void ScanImages(string file, string text)
    {
        foreach (Match m in McrImage().Matches(text))
        {
            var tag = m.Groups["tag"].Value;
            var line = LineOf(text, m.Index);
            if (tag.Length == 0 || tag.Contains('$') || MajorMinor().Match(tag) is not { Success: true } v)
            {
                Add(new("container", Severity.Info, Rel(file), line, m.Value, tag.Length == 0 ? "latest" : tag,
                    "Image tag is missing or comes from a variable; its .NET version cannot be checked statically.",
                    "Pin an explicit tag, e.g. 10.0, and check the build argument that feeds it."));
                continue;
            }
            var channel = $"{v.Groups["maj"].Value}.{v.Groups["min"].Value}";
            var (sev, msg) = ClassifyChannel(channel, $"Image {m.Value}");
            msg = msg.Replace(" targets ", " runs ", StringComparison.Ordinal);
            if (sev == Severity.Info && ImagePatch().Match(tag) is { Success: true } ip)
            {
                var patch = int.Parse(ip.Groups["pat"].Value, CultureInfo.InvariantCulture);
                var runtime = m.Groups["repo"].Value == "sdk" && patch >= 100
                    ? RuntimeOfSdk(channel, $"{channel}.{patch}")
                    : new Version(int.Parse(v.Groups["maj"].Value, CultureInfo.InvariantCulture), int.Parse(v.Groups["min"].Value, CultureInfo.InvariantCulture), patch);
                if (runtime is not null)
                    AddPatchFinding(file, line, m.Value, tag, runtime, $"Image {m.Value}",
                        $"Raise the tag to the latest patch ({{0}}) or use the floating tag {channel} and rebuild with --pull after each .NET release.");
            }
            else if (sev == Severity.Info && lifecycle.Find(channel)?.LatestRuntime is { } latest)
            {
                msg += $" Floating tag: the image only gets runtime security fixes ({latest} today) when it is rebuilt with --pull and redeployed.";
            }
            string? rec = null;
            if (sev != Severity.Info && target is not null)
            {
                rec = $"Use mcr.microsoft.com/dotnet/{m.Groups["repo"].Value}:{target.Version}.";
                if (target.Major >= 10)
                {
                    rec += " Since .NET 10 the default tag is Ubuntu 24.04, not Debian: check apt package names.";
                    if (text.Contains("1000", StringComparison.Ordinal)) rec += " UID/GID 1000 is already taken by the 'ubuntu' user.";
                }
            }
            Add(new("container", sev, Rel(file), line, m.Value, tag, msg, rec));
        }
        foreach (Match m in LegacyHubImage().Matches(text))
        {
            Add(new("container", Severity.Critical, Rel(file), LineOf(text, m.Index), m.Value, m.Groups["tag"].Value,
                $"Image {m.Value} comes from the retired Docker Hub repository 'microsoft/{m.Groups["repo"].Value}', which gets no updates.",
                target is null ? "Move to mcr.microsoft.com/dotnet/*." : $"Move to mcr.microsoft.com/dotnet/aspnet:{target.Version} (runtime) and mcr.microsoft.com/dotnet/sdk:{target.Version} (build)."));
        }
    }

    [GeneratedRegex(@"^(?<indent>\s*)-?\s*dotnet-version\s*:\s*(?<value>.*)$")]
    private static partial Regex SetupDotnetKey();

    [GeneratedRegex(@"^\s*-?\s*['""]?(?<maj>\d+)\.(?<min>\d+|x)")]
    private static partial Regex VersionListItem();

    [GeneratedRegex(@"\b(?:DOTNET|NET)[_-]?(?:SDK[_-]?|CORE[_-]?)?VERSION\s*[:=]\s*['""]?(?<maj>\d+)\.(?<min>\d+|x)", RegexOptions.IgnoreCase)]
    private static partial Regex VersionVariable();

    [GeneratedRegex(@"^\s*(?:version|packageType)\s*:\s*['""]?(?<maj>\d+)\.(?<min>\d+|x)")]
    private static partial Regex UseDotnetVersion();

    void ScanVersionPins(string file, string text)
    {
        var lines = text.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var l = lines[i];
            if (SetupDotnetKey().Match(l) is { Success: true } key)
            {
                var value = key.Groups["value"].Value.Trim();
                if (VersionListItem().Match(value) is { Success: true } single)
                {
                    AddPin(file, i + 1, "dotnet-version", single);
                }
                else
                {
                    var indent = key.Groups["indent"].Value.Length;
                    for (var j = i + 1; j < lines.Length; j++)
                    {
                        var next = lines[j];
                        if (next.Trim().Length == 0) continue;
                        if (next.Length - next.TrimStart().Length <= indent && !next.TrimStart().StartsWith('-')) break;
                        if (VersionListItem().Match(next) is { Success: true } item) AddPin(file, j + 1, "dotnet-version", item);
                        else break;
                    }
                }
            }
            if (l.Contains("UseDotNet@", StringComparison.Ordinal))
            {
                for (var j = i + 1; j < Math.Min(lines.Length, i + 10); j++)
                {
                    if (UseDotnetVersion().Match(lines[j]) is { Success: true } uv && lines[j].TrimStart().StartsWith("version", StringComparison.Ordinal))
                    {
                        AddPin(file, j + 1, "UseDotNet version", uv);
                        break;
                    }
                }
            }
            if (VersionVariable().Match(l) is { Success: true } pin) AddPin(file, i + 1, "DOTNET_VERSION", pin);
        }
    }

    void AddPin(string file, int line, string subject, Match m)
    {
        var min = m.Groups["min"].Value == "x" ? "0" : m.Groups["min"].Value;
        var version = $"{m.Groups["maj"].Value}.{min}";
        var (sev, msg) = ClassifyChannel(version, $"CI/build pin '{subject}'");
        msg = msg.Replace(" targets ", " installs ", StringComparison.Ordinal);
        Add(new("ci", sev, Rel(file), line, subject, $"{m.Groups["maj"].Value}.{m.Groups["min"].Value}", msg,
            sev == Severity.Info || target is null ? null : $"Install {target.Major}.0.x instead."));
    }

    // ---- NuGet audit -----------------------------------------------------------------------------------------

    public void AuditPackages(bool restore, TextWriter log)
    {
        var sdkProjects = projects.Where(p =>
        {
            var head = File.ReadAllText(p);
            return head.Contains("Sdk=\"", StringComparison.OrdinalIgnoreCase) || head.Contains("<Sdk ", StringComparison.OrdinalIgnoreCase);
        }).OrderBy(p => p, StringComparer.Ordinal).ToList();

        var vulnerable = new Dictionary<string, (Finding Finding, SortedSet<string> Projects)>();
        var deprecated = new Dictionary<string, (Finding Finding, SortedSet<string> Projects)>();

        foreach (var project in sdkProjects)
        {
            var rel = Rel(project);
            log.WriteLine($"auditing {rel}");
            if (restore)
            {
                var (code, _, err) = Run("restore", project, "--verbosity", "quiet");
                if (code != 0)
                {
                    Add(new("package-audit", Severity.Low, rel, 0, "restore", "failed",
                        $"dotnet restore failed, packages were not audited: {FirstLine(err)}",
                        "Restore the project (private feeds, missing SDK, global.json) and re-run, or audit it in your IDE."));
                    continue;
                }
            }
            CollectFrom(project, rel, "--vulnerable", vulnerable, ParseVulnerable);
            CollectFrom(project, rel, "--deprecated", deprecated, ParseDeprecated);
        }

        // A deprecated package drags its own deprecated dependencies (xunit -> xunit.core, ...): report them under the parent.
        var deprecatedIds = deprecated.Values.Select(d => d.Finding.Subject).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var key in deprecated.Keys.ToList())
        {
            var (f, ps) = deprecated[key];
            var parent = deprecatedIds.FirstOrDefault(p => f.Subject.StartsWith(p + ".", StringComparison.OrdinalIgnoreCase));
            if (parent is null || !f.Message.Contains("(transitive)", StringComparison.Ordinal)) continue;
            deprecated.Remove(key);
            var parentKey = deprecated.Keys.First(k => k.StartsWith(parent + "|", StringComparison.OrdinalIgnoreCase));
            var (pf, pps) = deprecated[parentKey];
            deprecated[parentKey] = (pf with { Message = $"{pf.Message} Also deprecated: {f.Subject} {f.Current}." }, pps);
        }

        foreach (var (f, ps) in vulnerable.Values.Concat(deprecated.Values))
            Add(f with { File = ps.Count == 1 ? ps.First() : $"{ps.First()} (+{ps.Count - 1} more)", Message = $"{f.Message} Used by: {string.Join(", ", ps)}." });
    }

    void CollectFrom(string project, string rel, string mode,
        Dictionary<string, (Finding, SortedSet<string>)> sink,
        Func<JsonNode, bool, string, IEnumerable<Finding>> parse)
    {
        var (code, stdout, stderr) = Run("list", project, "package", mode, "--include-transitive", "--format", "json");
        JsonNode? json = null;
        try { json = JsonNode.Parse(stdout); } catch (JsonException) { }
        if (json is null)
        {
            Add(new("package-audit", Severity.Low, rel, 0, mode, code.ToString(CultureInfo.InvariantCulture),
                $"'dotnet list package {mode}' did not return JSON: {FirstLine(stderr.Length > 0 ? stderr : stdout)}",
                "Requires the .NET 8+ SDK and a restored project."));
            return;
        }
        foreach (var fw in json["projects"]?.AsArray().SelectMany(p => p?["frameworks"]?.AsArray() ?? []) ?? [])
        {
            if (fw is null) continue;
            var framework = (string?)fw["framework"] ?? "";
            foreach (var (list, transitive) in new[] { (fw["topLevelPackages"], false), (fw["transitivePackages"], true) })
            {
                foreach (var pkg in list?.AsArray() ?? [])
                {
                    if (pkg is null) continue;
                    foreach (var f in parse(pkg, transitive, framework))
                    {
                        var key = $"{f.Subject}|{f.Current}|{f.Url}";
                        if (!sink.TryGetValue(key, out var entry)) sink[key] = entry = (f, new SortedSet<string>(StringComparer.Ordinal));
                        else if (!transitive && entry.Item1.Message.Contains("(transitive)", StringComparison.Ordinal)) sink[key] = entry = (f, entry.Item2);
                        entry.Item2.Add(rel);
                    }
                }
            }
        }
    }

    static IEnumerable<Finding> ParseVulnerable(JsonNode pkg, bool transitive, string framework)
    {
        var id = (string?)pkg["id"] ?? "?";
        var version = (string?)pkg["resolvedVersion"] ?? "?";
        foreach (var v in pkg["vulnerabilities"]?.AsArray() ?? [])
        {
            var severity = ((string?)v?["severity"] ?? "").ToLowerInvariant() switch
            {
                "critical" => Severity.Critical,
                "high" => Severity.High,
                "moderate" or "medium" => Severity.Medium,
                _ => Severity.Low,
            };
            var url = (string?)v?["advisoryurl"];
            yield return new("package-vulnerable", severity, "", 0, id, version,
                $"{id} {version}{(transitive ? " (transitive)" : "")} has a known {((string?)v?["severity"] ?? "unknown").ToLowerInvariant()} vulnerability.",
                transitive
                    ? "Upgrade the top-level package that brings it in; if none fixes it, add a direct PackageReference to a patched version."
                    : "Upgrade to a patched version (see the advisory).",
                url);
        }
    }

    static IEnumerable<Finding> ParseDeprecated(JsonNode pkg, bool transitive, string framework)
    {
        var reasons = pkg["deprecationReasons"]?.AsArray().Select(r => (string?)r).Where(r => r is not null).ToList();
        if (reasons is not { Count: > 0 }) yield break;
        var id = (string?)pkg["id"] ?? "?";
        var version = (string?)pkg["resolvedVersion"] ?? "?";
        var range = (string?)pkg["alternativePackage"]?["versionRange"];
        var alt = (string?)pkg["alternativePackage"]?["id"] is { } altId
            ? range is null or "*" or ">= 0.0.0" ? altId : $"{altId} {range}"
            : null;
        var critical = reasons.Any(r => r!.Contains("Critical", StringComparison.OrdinalIgnoreCase));
        yield return new("package-deprecated", critical ? Severity.High : Severity.Low, "", 0, id, version,
            $"{id} {version}{(transitive ? " (transitive)" : "")} is deprecated ({string.Join(", ", reasons)}).",
            alt is { Length: > 0 } ? $"Replace with {alt}." : "Find a maintained replacement or a newer version.");
    }

    static string FirstLine(string s) =>
        s.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? "(no output)";

    static (int Code, string StdOut, string StdErr) Run(string verb, string project, params string[] rest)
    {
        var psi = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(project)!,
        };
        psi.ArgumentList.Add(verb);
        psi.ArgumentList.Add(project);
        foreach (var r in rest) psi.ArgumentList.Add(r);
        psi.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        psi.Environment["DOTNET_NOLOGO"] = "1";

        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(TimeSpan.FromMinutes(5)))
        {
            p.Kill(entireProcessTree: true);
            return (-1, "", "timed out after 5 minutes");
        }
        return (p.ExitCode, stdout.Result, stderr.Result);
    }
}

sealed class Report(string root, DateOnly asOf, Lifecycle lifecycle, Channel? target, IEnumerable<Finding> all, Severity? failOn, string toolVersion)
{
    readonly List<Finding> findings = all
        .OrderByDescending(f => f.Severity).ThenBy(f => f.Category, StringComparer.Ordinal)
        .ThenBy(f => f.File, StringComparer.Ordinal).ThenBy(f => f.Line).ToList();

    public bool Failed => failOn is { } t && findings.Any(f => f.Severity >= t);

    int Count(Severity s) => findings.Count(f => f.Severity == s);

    public string ToJson()
    {
        var o = new JsonObject
        {
            ["tool"] = "dotnet-eol-guard",
            ["version"] = toolVersion,
            ["path"] = root,
            ["asOf"] = asOf.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            ["lifecycleSource"] = lifecycle.Source,
            ["target"] = target is null ? null : new JsonObject
            {
                ["channel"] = target.Version,
                ["releaseType"] = target.ReleaseType,
                ["eol"] = target.Eol?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                ["latestRuntime"] = target.LatestRuntime,
                ["latestSdk"] = target.LatestSdk,
            },
            ["failOn"] = failOn?.ToString().ToLowerInvariant() ?? "none",
            ["failed"] = Failed,
            ["summary"] = new JsonObject(Enum.GetValues<Severity>().Reverse()
                .Select(s => KeyValuePair.Create(s.ToString().ToLowerInvariant(), (JsonNode?)Count(s)))),
            ["findings"] = new JsonArray(findings.Select(f => (JsonNode)new JsonObject
            {
                ["category"] = f.Category,
                ["severity"] = f.Severity.ToString().ToLowerInvariant(),
                ["file"] = f.File,
                ["line"] = f.Line,
                ["subject"] = f.Subject,
                ["current"] = f.Current,
                ["message"] = f.Message,
                ["recommendation"] = f.Recommendation,
                ["url"] = f.Url,
            }).ToArray()),
        };
        return o.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    public string ToMarkdown()
    {
        var sb = new StringBuilder();
        sb.AppendLine("# dotnet-eol-guard report").AppendLine();
        sb.AppendLine($"Scanned `{Path.GetFileName(root.TrimEnd(Path.DirectorySeparatorChar))}` as of {asOf:yyyy-MM-dd} · lifecycle data: {lifecycle.Source}").AppendLine();
        sb.AppendLine(target is null
            ? "**No supported LTS found to recommend.**"
            : $"Recommended target: **{target.Label}**, supported until {target.Eol?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "TBD"} · latest runtime {target.LatestRuntime} · SDK {target.LatestSdk}");
        sb.AppendLine();

        var eolChannels = findings.Where(f => f.Severity == Severity.Critical && f.Message.Contains("out of support since", StringComparison.Ordinal))
            .Select(f => Regex.Match(f.Message, @"\.NET \d+\.\d+").Value).Where(v => v.Length > 0).Distinct().OrderBy(v => v, StringComparer.Ordinal).ToList();
        if (eolChannels.Count > 0)
        {
            sb.AppendLine($"> [!WARNING]");
            sb.AppendLine($"> **{string.Join(", ", eolChannels)} {(eolChannels.Count == 1 ? "is" : "are")} out of support.** Microsoft no longer ships security patches for {(eolChannels.Count == 1 ? "it" : "them")}, so known and future vulnerabilities stay open; updating packages alone does not fix that. Migrate to {(target is null ? "a supported version" : $"**{target.Label}**")}.");
            sb.AppendLine();
        }

        sb.AppendLine("| Severity | Findings |").AppendLine("|---|---|");
        foreach (var s in Enum.GetValues<Severity>().Reverse()) sb.AppendLine($"| {Icon(s)} {s} | {Count(s)} |");
        sb.AppendLine();
        sb.AppendLine(failOn is null
            ? "Result: report only (`--fail-on none`)."
            : Failed ? $"Result: **FAIL**, there are findings at or above `{failOn.ToString()!.ToLowerInvariant()}`."
                     : $"Result: **PASS**, nothing at or above `{failOn.ToString()!.ToLowerInvariant()}`.");
        sb.AppendLine();

        foreach (var s in Enum.GetValues<Severity>().Reverse())
        {
            var group = findings.Where(f => f.Severity == s).ToList();
            if (group.Count == 0) continue;
            var info = s == Severity.Info;
            if (info) sb.AppendLine($"<details><summary>{Icon(s)} Info: {group.Count} supported or unverifiable items (no action needed)</summary>").AppendLine();
            else sb.AppendLine($"## {Icon(s)} {s}").AppendLine();
            sb.AppendLine("| Where | Category | Finding | Recommendation |").AppendLine("|---|---|---|---|");
            foreach (var f in group)
            {
                var where = f.Line > 0 ? $"`{f.File}:{f.Line}`" : $"`{f.File}`";
                var msg = f.Url is null ? f.Message : $"{f.Message} [advisory]({f.Url})";
                sb.AppendLine($"| {where} | {f.Category} | {Esc(msg)} | {Esc(f.Recommendation ?? "-")} |");
            }
            sb.AppendLine();
            if (info) sb.AppendLine("</details>").AppendLine();
        }
        if (findings.Count == 0) sb.AppendLine("No .NET projects, images or CI pins found.").AppendLine();
        sb.AppendLine($"<sub>dotnet-eol-guard {toolVersion}</sub>");
        return sb.ToString();
    }

    static string Icon(Severity s) => s switch
    {
        Severity.Critical => "🔴",
        Severity.High => "🟠",
        Severity.Medium => "🟡",
        Severity.Low => "🔵",
        _ => "⚪",
    };

    static string Esc(string s) => s.Replace("|", "\\|", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);
}
