using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace Aaron.Pina.Blog.Article._07.Other;

public static class Configuration
{
    public static class JwtBearer
    {
        public static readonly Action<JwtBearerOptions> Options = options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ClockSkew = TimeSpan.Zero,
                ValidateAudience = true,
                ValidateLifetime = true
            };
            options.MapInboundClaims = false;
            options.RequireHttpsMetadata = false;
            options.Audience = "https://localhost";
            options.Authority = "https://localhost:5001";
        };
    }

}
