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
using ArtServiceApi.Repositories.Implementaciones;

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
        private readonly RefreshTokenRepository _refreshTokenRepository;

        public AuthController(
            UserManager<Usuario> userManager,
            SignInManager<Usuario> signInManager,
            IConfiguration configuration,
            ITokenService tokenService,
            RefreshTokenRepository refreshTokenRepository)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _tokenService = tokenService;
            _refreshTokenRepository = refreshTokenRepository;
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

            // Genera y guarda el refresh token en la base de datos
            var refreshTokenValue = GenerateRefreshToken();
            var refreshToken = new RefreshToken
            {
                UserId = user.Id,
                Token = refreshTokenValue,
                Expiration = DateTime.UtcNow.AddDays(Convert.ToInt32(_configuration["Jwt:RefreshTokenExpireDays"] ?? "7")),
                IsRevoked = false
            };
            await _refreshTokenRepository.AddAsync(refreshToken);

            return Ok(new { token, refreshToken = refreshTokenValue });
        }

        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest model)
        {
            if (string.IsNullOrWhiteSpace(model?.Token) || string.IsNullOrWhiteSpace(model?.RefreshToken))
                return BadRequest("Token y refresh token son requeridos");

            var principal = GetPrincipalFromExpiredToken(model.Token!);
            if (principal == null)
                return BadRequest("Token inválido");

            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            // Si userId parece ser un username, busca el usuario por username y obtén el Id real
            if (!string.IsNullOrEmpty(userId) && !userId.All(char.IsDigit))
            {
                var userByName = await _userManager.FindByNameAsync(userId);
                userId = userByName?.Id;
            }
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            // Busca el refresh token en la base de datos
            var dbRefreshToken = await _refreshTokenRepository.GetByTokenAsync(model.RefreshToken!);
            if (dbRefreshToken == null || dbRefreshToken.UserId != userId || dbRefreshToken.Expiration < DateTime.UtcNow)
                return Unauthorized();

            // Revoca el refresh token anterior
            await _refreshTokenRepository.RevokeAsync(dbRefreshToken);

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

            // Genera y guarda el nuevo refresh token
            var newRefreshTokenValue = GenerateRefreshToken();
            var newRefreshToken = new RefreshToken
            {
                UserId = user.Id,
                Token = newRefreshTokenValue,
                Expiration = DateTime.UtcNow.AddDays(Convert.ToInt32(_configuration["Jwt:RefreshTokenExpireDays"] ?? "7")),
                IsRevoked = false
            };
            await _refreshTokenRepository.AddAsync(newRefreshToken);

            return Ok(new { token = newJwtToken, refreshToken = newRefreshTokenValue });
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
    }

    public class LoginRequest
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
    }
}
