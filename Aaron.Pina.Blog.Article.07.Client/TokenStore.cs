namespace Aaron.Pina.Blog.Article._07.Client;

public class TokenStore
{
    public string?   AccessToken          { get; set; }
    public string?   RefreshToken         { get; set; }
    public DateTime? AccessTokenExpiresAt { get; set; }
}
