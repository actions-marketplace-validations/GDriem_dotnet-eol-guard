var app = WebApplication.CreateBuilder(args).Build();
app.MapGet("/", () => Newtonsoft.Json.JsonConvert.SerializeObject(new { ok = true }));
app.Run();
