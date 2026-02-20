namespace Aaron.Pina.Blog.Article._07.Server;

public record OpenidConfiguration
{
    public string Issuer                { get; init; } = "https://localhost:5001";
    public string JwksUri               { get; init; } = "https://localhost:5001/.well.known/jwks.json";
    public string AuthorizationEndpoint { get; init; } = "https://localhost:5001/authorize";
    public string TokenEndpoint         { get; init; } = "https://localhost:5001/token";
}
