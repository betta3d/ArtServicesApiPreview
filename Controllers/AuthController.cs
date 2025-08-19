#nullable enable
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ArtServiceApi.Domain.Entidades;
using ArtServiceApi.Services.Interfaces;

namespace ArtServiceApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class AuthController : ControllerBase
    {
    private readonly UserManager<Usuario> _userManager;
    private readonly SignInManager<Usuario> _signInManager;
    private readonly IConfiguration _configuration;
    private readonly ITokenService _tokenService;
    // Almacenamiento en memoria para refresh tokens (demo)
    private static Dictionary<string, string> _refreshTokens = new();

    public AuthController(UserManager<Usuario> userManager, SignInManager<Usuario> signInManager, IConfiguration configuration, ITokenService tokenService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
        _tokenService = tokenService;
    }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginRequest model)
        {
            if (string.IsNullOrWhiteSpace(model?.Username) || string.IsNullOrWhiteSpace(model?.Password))
                return BadRequest("Usuario y contraseña son requeridos");

            var user = await _userManager.FindByNameAsync(model.Username!);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password!))
                return Unauthorized();

            var identity = new ClaimsIdentity(new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id ?? string.Empty)
            });
            var expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpireMinutes"] ?? "60"));
            var token = _tokenService.GenerateToken(identity, expires);
            var refreshToken = GenerateRefreshToken();
            _refreshTokens[user.Id] = refreshToken;
            return Ok(new { token, refreshToken });
        }
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest model)
        {
            if (string.IsNullOrWhiteSpace(model?.Token) || string.IsNullOrWhiteSpace(model?.RefreshToken))
                return BadRequest("Token y refresh token son requeridos");

            var principal = GetPrincipalFromExpiredToken(model.Token!);
            if (principal == null)
                return BadRequest("Token inválido");

            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId) || !_refreshTokens.TryGetValue(userId ?? string.Empty, out var savedRefreshToken) || savedRefreshToken != model.RefreshToken)
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return Unauthorized();

            var identity = new ClaimsIdentity(new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id ?? string.Empty)
            });
            var expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpireMinutes"] ?? "60"));
            var newJwtToken = _tokenService.GenerateToken(identity, expires);
            var newRefreshToken = GenerateRefreshToken();
            _refreshTokens[user.Id] = newRefreshToken;
            return Ok(new { token = newJwtToken, refreshToken = newRefreshToken });
        }
        private string GenerateRefreshToken()
        {
            var length = int.Parse(_configuration["Jwt:RefreshTokenLength"] ?? "32");
            var randomBytes = new byte[length];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }
        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            var jwtSettings = _configuration.GetSection("Jwt");
            var keyStr = jwtSettings["Key"];
            if (string.IsNullOrEmpty(keyStr)) throw new Exception("JWT Key no configurado");
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtSettings["Issuer"],
                ValidAudience = jwtSettings["Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyStr)),
                ValidateLifetime = false // Importante para permitir tokens expirados
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
                if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                    !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    return null;
                }
                return principal;
            }
            catch
            {
                return null;
            }
        }
        public class RefreshRequest
        {
            public string? Token { get; set; }
            public string? RefreshToken { get; set; }
        }

    // Token generation is now handled by ITokenService
    }

    public class LoginRequest
    {
    public string? Username { get; set; }
    public string? Password { get; set; }
    }
}
