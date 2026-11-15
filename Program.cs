using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http.Features;

var builder = WebApplication.CreateBuilder(args);
builder.Services.Configure<FormOptions>(o => o.MultipartBodyLengthLimit = 100_000_000);
builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 100_000_000);
var app = builder.Build();
app.UseDefaultFiles();
app.UseStaticFiles();

var cfg = app.Configuration;
int criticalAfter = cfg.GetValue("Portal:CriticalAfter", 10);
long maxFile = cfg.GetValue("Portal:MaxFileBytes", 1073741824L);
bool devOtp = cfg.GetValue("Portal:DevShowOtp", true);
string secret = cfg.GetValue("Portal:Secret", "secret")!;
var leaders = cfg.GetSection("Leaders").Get<List<Leader>>() ?? new();
var store = new Store(Path.Combine(app.Environment.ContentRootPath, "Data"), maxFile);
var uploads = Path.Combine(app.Environment.WebRootPath ?? Path.Combine(app.Environment.ContentRootPath, "wwwroot"), "uploads");
Directory.CreateDirectory(uploads);

var otps = new ConcurrentDictionary<string, (string Code, DateTime Exp, int Tries)>();
var sessions = new ConcurrentDictionary<string, Session>();

string Norm(string? s) => new string((s ?? "").Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();
string Hash(string s) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret + "|" + s)));
Session? Auth(HttpRequest r)
{
    var id = r.Headers["X-Device"].ToString();
    if (string.IsNullOrWhiteSpace(id)) id = r.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "anon";
    return new Session(Hash(id), null);
}
object Dto(Issue i) => new
{
    i.Id, i.State, i.District, i.Area, i.Description, i.MediaUrl, i.MediaType, i.CreatedAt,
    Count = i.Voters.Count, Critical = i.Voters.Count > criticalAfter
};

// ---------- OTP login ----------
app.MapPost("/api/otp/request", (OtpReq req) =>
{
    var c = Norm(req.Contact);
    if (c.Length < 6) return Results.BadRequest(new { error = "Enter a valid phone number or email." });
    var code = RandomNumberGenerator.GetInt32(100000, 999999).ToString();
    otps[c] = (code, DateTime.UtcNow.AddMinutes(5), 0);
    // TODO: plug in SMS/email provider here (Twilio, MSG91, SendGrid...)
    Console.WriteLine($"[OTP] {req.Contact} -> {code}");
    return Results.Ok(new { sent = true, devOtp = devOtp ? code : null });
});

app.MapPost("/api/otp/verify", (VerifyReq req) =>
{
    var c = Norm(req.Contact);
    if (!otps.TryGetValue(c, out var o) || o.Exp < DateTime.UtcNow || o.Tries >= 5)
        return Results.BadRequest(new { error = "OTP expired. Request a new one." });
    if (o.Code != req.Otp?.Trim())
    {
        otps[c] = (o.Code, o.Exp, o.Tries + 1);
        return Results.BadRequest(new { error = "Wrong OTP." });
    }
    otps.TryRemove(c, out _);
    var leader = leaders.FirstOrDefault(l => Norm(l.Contact) == c);
    var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    sessions[token] = new Session(Hash(c), leader);
    return Results.Ok(new { token, isLeader = leader != null, leader = leader == null ? null : new { leader.Name, leader.State, leader.District, leader.Area } });
});

// ---------- Issues ----------
app.MapGet("/api/issues", (string? state, string? district, string? area) =>
    Results.Ok(store.Query(state, district, area).Select(Dto)));

app.MapPost("/api/issues", async (HttpRequest req) =>
{
    var s = Auth(req); if (s == null) return Results.Unauthorized();
    var f = await req.ReadFormAsync();
    string state = f["state"].ToString().Trim(), district = f["district"].ToString().Trim(),
           area = f["area"].ToString().Trim(), desc = f["description"].ToString().Trim();
    if (state == "" || district == "" || area == "" || desc.Length < 10)
        return Results.BadRequest(new { error = "State, district, area and a description (10+ characters) are required." });

    string? url = null, type = null;
    var file = f.Files.FirstOrDefault();
    if (file != null && file.Length > 0)
    {
        var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
        string[] img = { ".jpg", ".jpeg", ".png", ".webp", ".gif" }, vid = { ".mp4", ".webm", ".mov" };
        if (img.Contains(ext)) type = "image"; else if (vid.Contains(ext)) type = "video";
        else return Results.BadRequest(new { error = "Only photos (jpg, png, webp, gif) or videos (mp4, webm, mov)." });
        var name = Guid.NewGuid().ToString("N") + ext;
        await using var fs = File.Create(Path.Combine(uploads, name));
        await file.CopyToAsync(fs);
        url = "/uploads/" + name;
    }
    var (issue, merged) = store.AddOrMerge(new Issue
    {
        Id = Guid.NewGuid().ToString("N"), State = state, District = district, Area = area,
        Description = desc, MediaUrl = url, MediaType = type, CreatedAt = DateTime.UtcNow
    }, s.UserHash);
    return Results.Ok(new { merged, issue = Dto(issue) });
});

app.MapPost("/api/issues/{id}/me-too", (string id, HttpRequest req) =>
{
    var s = Auth(req); if (s == null) return Results.Unauthorized();
    var i = store.Vote(id, s.UserHash);
    return i == null ? Results.NotFound() : Results.Ok(Dto(i));
});

// ---------- Leader view ----------
app.MapGet("/api/leader/issues", (HttpRequest req) =>
{
    var s = Auth(req); if (s == null) return Results.Unauthorized();
    if (s.Leader == null) return Results.Forbid();
    var l = s.Leader;
    var list = store.Query(l.State, l.District, string.IsNullOrWhiteSpace(l.Area) ? null : l.Area)
        .OrderByDescending(i => i.Voters.Count).ThenByDescending(i => i.CreatedAt);
    return Results.Ok(list.Select(Dto));
});

// ---------- Leaderboard of areas ----------
app.MapGet("/api/leaderboard", () =>
    Results.Ok(store.Query(null, null, null)
        .GroupBy(i => new { i.State, i.District, i.Area }, (k, g) => new
        {
            k.State, k.District, k.Area,
            Problems = g.Count(),
            Reports = g.Sum(x => x.Voters.Count),
            Critical = g.Count(x => x.Voters.Count > criticalAfter)
        })
        .OrderByDescending(x => x.Critical).ThenByDescending(x => x.Reports).Take(20)));

app.Run();

// ================= Models & Storage =================
record OtpReq(string Contact);
record VerifyReq(string Contact, string Otp);
record Session(string UserHash, Leader? Leader);
class Leader { public string Contact { get; set; } = ""; public string Name { get; set; } = ""; public string State { get; set; } = ""; public string District { get; set; } = ""; public string Area { get; set; } = ""; }

class Issue
{
    public string Id { get; set; } = "";
    public string State { get; set; } = "";
    public string District { get; set; } = "";
    public string Area { get; set; } = "";
    public string Description { get; set; } = "";
    public string? MediaUrl { get; set; }
    public string? MediaType { get; set; }
    public DateTime CreatedAt { get; set; }
    public HashSet<string> Voters { get; set; } = new();
}
record Event(string T, Issue? Issue, string? Id, string? Voter);

class Store
{
    readonly string dir; readonly long maxBytes; readonly object gate = new();
    readonly Dictionary<string, Issue> issues = new();
    static readonly JsonSerializerOptions Opt = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public Store(string dir, long maxBytes)
    {
        this.dir = dir; this.maxBytes = maxBytes; Directory.CreateDirectory(dir);
        foreach (var f in Directory.GetFiles(dir, "issues-*.json").OrderBy(x => x))
            foreach (var line in File.ReadLines(f))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var e = JsonSerializer.Deserialize<Event>(line, Opt)!;
                if (e.T == "create" && e.Issue != null) issues[e.Issue.Id] = e.Issue;
                else if (e.T == "vote" && e.Id != null && issues.TryGetValue(e.Id, out var i)) i.Voters.Add(e.Voter!);
            }
    }

    string CurrentFile()
    {
        var files = Directory.GetFiles(dir, "issues-*.json").OrderBy(x => x).ToList();
        if (files.Count == 0) return Path.Combine(dir, "issues-0001.json");
        var last = files[^1];
        if (new FileInfo(last).Length < maxBytes) return last;
        var n = int.Parse(Path.GetFileNameWithoutExtension(last).Split('-')[1]) + 1;
        return Path.Combine(dir, $"issues-{n:0000}.json");
    }
    void Append(Event e) => File.AppendAllText(CurrentFile(), JsonSerializer.Serialize(e, Opt) + "\n");

    public IEnumerable<Issue> Query(string? state, string? district, string? area)
    {
        lock (gate)
            return issues.Values
                .Where(i => (string.IsNullOrWhiteSpace(state) || Eq(i.State, state))
                         && (string.IsNullOrWhiteSpace(district) || Eq(i.District, district))
                         && (string.IsNullOrWhiteSpace(area) || Eq(i.Area, area)))
                .OrderByDescending(i => i.CreatedAt).ToList();
    }
    static bool Eq(string a, string b) => string.Equals(a.Trim(), b.Trim(), StringComparison.OrdinalIgnoreCase);

    static HashSet<string> Tokens(string s) =>
        new(System.Text.RegularExpressions.Regex.Matches(s.ToLowerInvariant(), @"[a-z0-9\u0900-\u0dff]{3,}").Select(m => m.Value));

    public (Issue, bool) AddOrMerge(Issue n, string voter)
    {
        lock (gate)
        {
            var t = Tokens(n.Description);
            foreach (var i in issues.Values.Where(i => Eq(i.State, n.State) && Eq(i.District, n.District) && Eq(i.Area, n.Area)))
            {
                var o = Tokens(i.Description);
                if (t.Count == 0 || o.Count == 0) continue;
                double jac = (double)t.Intersect(o).Count() / t.Union(o).Count();
                if (jac >= 0.5)
                {
                    if (i.Voters.Add(voter)) Append(new Event("vote", null, i.Id, voter));
                    return (i, true);
                }
            }
            n.Voters.Add(voter);
            issues[n.Id] = n;
            Append(new Event("create", n, null, null));
            return (n, false);
        }
    }

    public Issue? Vote(string id, string voter)
    {
        lock (gate)
        {
            if (!issues.TryGetValue(id, out var i)) return null;
            if (i.Voters.Add(voter)) Append(new Event("vote", null, id, voter));
            return i;
        }
    }

    
}