using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("cookie")
    .AddCookie("cookie", options =>
    {
        options.LoginPath = "/login";
        var del = options.Events.OnRedirectToAccessDenied;
        options.Events.OnRedirectToAccessDenied = context =>
        {
            if (context.Request.Path.StartsWithSegments("/youtube"))
            {
                return context.HttpContext.ChallengeAsync("youtube");
            }
            return del(context);
        };
    })
    .AddOAuth("youtube", options =>
    {
        options.SignInScheme = "cookie";
        options.ClientId="Secrets.ClientId";
        options.ClientSecret = "Secrets.ClientSecret";
        options.SaveTokens = false;

        options.Scope.Clear();
        options.Scope.Add("https://www.googleapis.com/oauth/youtube.readonly");

        options.AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
        options.TokenEndpoint = "https://oauth2/googleapis.com/token";
        options.CallbackPath = "/oauth/youtube-cb";

        options.Events.OnCreatingTicket = async context =>
        {
            var database = context.HttpContext.RequestServices.GetRequiredService<DataBase>();
            var authenticationHandlerProvider = context.HttpContext.RequestServices.
                GetRequiredService<IAuthenticationHandlerProvider>();
            var handler = await authenticationHandlerProvider.GetHandlerAsync(context.HttpContext, "cookie");
            var authResult = await handler.AuthenticateAsync();
            if(!authResult.Succeeded)
            {
                context.Fail("Authenticate Failed");
                return;
            }
            var claimsPrincipal = authResult.Principal;
            var userId = context.HttpContext.User.FindFirstValue("user_id");
            database[userId] = context.AccessToken;

            context.Principal = claimsPrincipal?.Clone();
            var identity = context.Principal.Identities.First(x => x.AuthenticationType == "cookie");
            identity.AddClaim(new Claim("youtube_token", "y"));
        };
    });

builder.Services.AddAuthorization(b => {

    b.AddPolicy("youtube_enabled", p =>
    {
        p.AddAuthenticationSchemes("cookie")
        .RequireClaim("youtube_token", "y")
        .RequireAuthenticatedUser();
    });
});

builder.Services.AddSingleton<DataBase>()
                .AddTransient<IClaimsTransformation, YoutubeTokenClaimsTransformation>();
builder.Services.AddHttpClient();

var app = builder.Build();

app.MapGet("/login", () =>  Results.SignIn(
        new ClaimsPrincipal(
            new ClaimsIdentity(
                new[] { new Claim("user_id", Guid.NewGuid().ToString()) },
                "cookie"
        ) 
    ),
    authenticationScheme:"cookie"
));

app.MapGet("/youtube/info", async (IHttpClientFactory clientFactory, DataBase db, HttpContext context) =>
{
    var user = context.User;
    var userId = user.FindFirstValue("user_id");
    var accessToken = context.User.FindFirstValue("youtube_access_token");
    var client = clientFactory.CreateClient();

    var request = new HttpRequestMessage(HttpMethod.Get, 
                      "https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true");
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    using var response = await client.SendAsync(request);
    return response.Content.ReadAsStringAsync();

}).RequireAuthorization("youtube_enabled");

app.Run();


public class DataBase : Dictionary<string,string>
{
}

public class YoutubeTokenClaimsTransformation : IClaimsTransformation
{
    private readonly DataBase _db;
    public YoutubeTokenClaimsTransformation(DataBase db)
    {
        _db = db;
    }
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var userId = principal.FindFirstValue("user_id");
        if(_db.ContainsKey(userId))
        {
            return Task.FromResult(principal);
        }
        var claimsPrincipal = principal.Clone();
        var accessToken = _db[userId];
        var identity = claimsPrincipal.Identities.First(x => x.AuthenticationType == "cookie");
        identity.AddClaim(new Claim("youtube_access_token","y"));
        return Task.FromResult<ClaimsPrincipal>(claimsPrincipal);
    }
}

