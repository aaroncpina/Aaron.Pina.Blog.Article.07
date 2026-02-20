namespace Aaron.Pina.Blog.Article._07.Shared.Responses;

public record TokenResponse(Guid Jti, string AccessToken, string RefreshToken, double AccessTokenExpiresIn);
