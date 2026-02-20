using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Aaron.Pina.Blog.Article._07.Server;

public class RsaKeyProvider : IDisposable
{
    private readonly RSA _rsa = RSA.Create(2048);

    public RsaKeyProvider()
    {
        SigningKey = new Lazy<RsaSecurityKey>(() => new RsaSecurityKey(_rsa));
        PublicKey =  new Lazy<RsaSecurityKey>(() => new RsaSecurityKey(_rsa.ExportParameters(false)));
    }
    
    public Lazy<RsaSecurityKey> SigningKey { get; }
    public Lazy<RsaSecurityKey> PublicKey  { get; }
    
    public void Dispose() => _rsa.Dispose();
}
