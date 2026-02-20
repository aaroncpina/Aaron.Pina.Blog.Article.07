using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Aaron.Pina.Blog.Article._07.Shared.Responses;
using Aaron.Pina.Blog.Article._07.Shared.Requests;
using Microsoft.Extensions.Caching.Distributed;
using Aaron.Pina.Blog.Article._07.Shared;
using Aaron.Pina.Blog.Article._07.Server;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Options;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddStackExchangeRedisCache(Configuration.RedisCache.Options);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(Configuration.JwtBearer.Options);
builder.Services.AddAuthorization(Configuration.Authorisation.Options);
builder.Services.AddSingleton<RsaKeyProvider>();
builder.Services.AddScoped<TokenRepository>();
builder.Services.AddScoped<UserRepository>();
builder.Services.AddDbContext<ServerDbContext>(Configuration.DbContext.Options);
builder.Services.Configure<TokenConfig>(builder.Configuration.GetSection(nameof(TokenConfig)));

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

using (var scope = app.Services.CreateScope())
    scope.ServiceProvider.GetRequiredService<ServerDbContext>().Database.EnsureCreated();

app.MapGet("/.well-known/openid-configuration", () => new OpenIdConnectConfiguration())
   .AllowAnonymous();

app.MapGet("/.well-known/jwks.json", (RsaKeyProvider rsaKeyProvider) =>
    {
        var key = rsaKeyProvider.PublicKey.Value;
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
        jwk.Kid = "2026-key-01";
        jwk.Use = "sig";
        var jwks = new JsonWebKeySet();
        jwks.Keys.Add(jwk);
        return Results.Json(jwks);
    })
   .WithName("JWKS")
   .AllowAnonymous();

app.MapGet("/{role}/register", (UserRepository repo, string role) =>
    {
        if (!Roles.ValidRoles.Contains(role)) return Results.BadRequest("Invalid role");
        var user = new UserEntity
        {
            Id = Guid.NewGuid(),
            Role = role
        };
        repo.AddUser(user);
        return Results.Ok(user.Id);
    })
   .AllowAnonymous();

app.MapGet("/token",
    (IOptionsSnapshot<TokenConfig> config,
     RsaKeyProvider rsaKeyProvider,
     TokenRepository tokenRepo,
     UserRepository userRepo,
     Guid userId) =>
    {
        var token = tokenRepo.TryGetTokenByUserId(userId);
        if (token is not null)
        {
            return Results.BadRequest(new
            {
                Error = "User already has an active token",
                Message = "Use the /refresh endpoint with your refresh token to get a new token"
            });
        }
        var user = userRepo.TryGetUserById(userId);
        if (user is null) return Results.BadRequest("Invalid user id");
        var jti = Guid.NewGuid();
        var now = DateTime.UtcNow;
        var refreshToken = TokenGenerator.GenerateRefreshToken();
        var accessToken = TokenGenerator.GenerateToken(
            rsaKeyProvider.PublicKey.Value, jti, userId, user.Role, now, config.Value.AccessTokenLifetime);
        var response = new TokenResponse(jti, accessToken, refreshToken, config.Value.AccessTokenLifetime);
        tokenRepo.SaveToken(new TokenEntity
        {
            RefreshTokenExpiresAt = now.AddMinutes(config.Value.RefreshTokenLifetime),
            RefreshToken = refreshToken,
            UserId = userId,
            CreatedAt = now
        });
        return Results.Ok(response);
    })
   .AllowAnonymous();

app.MapPost("/refresh", 
    (IOptionsSnapshot<TokenConfig> config,
     RsaKeyProvider rsaKeyProvider,
     TokenRepository tokenRepo,
     UserRepository userRepo,
     HttpContext context) =>
    {
        var refreshToken = context.Request.Form["refresh_token"].FirstOrDefault();
        if (string.IsNullOrEmpty(refreshToken)) return Results.BadRequest();
        var token = tokenRepo.TryGetTokenByRefreshToken(refreshToken);
        if (token is null) return Results.BadRequest();
        if (token.RefreshTokenExpiresAt < DateTime.UtcNow)
        {
            return Results.BadRequest(new
            {
                Error = "Refresh token has expired",
                Message = "Please login again to get a new token"
            });
        }
        var user = userRepo.TryGetUserById(token.UserId);
        if (user is null) return Results.BadRequest("Invalid user id");
        var jti = Guid.NewGuid();
        var now = DateTime.UtcNow;
        var newRefreshToken = TokenGenerator.GenerateRefreshToken();
        var accessToken = TokenGenerator.GenerateToken(
            rsaKeyProvider.PublicKey.Value, jti, token.UserId, user.Role, now, config.Value.AccessTokenLifetime);
        var response = new TokenResponse(jti, accessToken, newRefreshToken, config.Value.AccessTokenLifetime);
        token.RefreshTokenExpiresAt = now.AddMinutes(config.Value.RefreshTokenLifetime);
        token.RefreshToken = newRefreshToken;
        tokenRepo.UpdateToken(token);
        return Results.Ok(response);
    })
   .AllowAnonymous();

app.MapPost("/blacklist", async (IDistributedCache blacklist, BlacklistRequest request) =>
    {
        var expires = DateTimeOffset.UtcNow.AddSeconds(request.AccessTokenExpiresIn);
        if (expires < DateTimeOffset.UtcNow) return Results.BadRequest("Token already expired");
        await blacklist.SetStringAsync(request.Jti.ToString(), "revoked", new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = expires
        });
        return Results.Ok();
    })
   .RequireAuthorization("admin");

app.MapGet("/user", (HttpContext context) =>
    {
        var role = context.User.FindFirstValue("role");
        if (role is null) return Results.Unauthorized();
        var sub = context.User.FindFirstValue("sub");
        var parsed = Guid.TryParse(sub, out var userId); 
        if (!parsed) return Results.Unauthorized();
        return Results.Ok(new UserResponse(userId, role));
    })
   .RequireAuthorization();

app.Run();
