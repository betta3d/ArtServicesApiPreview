#nullable enable
using ArtServiceApi.Domain.Entidades;
using ArtServiceApi.Services.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace ArtServiceApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsuariosController : ControllerBase
    {
        private readonly IUsuarioService _usuarioService;

        public UsuariosController(IUsuarioService usuarioService)
        {
            _usuarioService = usuarioService;
        }

        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            var usuarios = await _usuarioService.GetAllAsync();
            return Ok(usuarios);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(string id)
        {
            var usuario = await _usuarioService.GetByIdAsync(id);
            if (usuario == null) return NotFound();
            return Ok(usuario);
        }

        [HttpPost]
        public async Task<IActionResult> Create([FromBody] UsuarioCreateRequest request)
        {
            var usuario = new Usuario
            {
                UserName = request.UserName,
                Email = request.Email,
                NombreCompleto = request.NombreCompleto,
                FechaNacimiento = request.FechaNacimiento
            };
            var result = await _usuarioService.CreateAsync(usuario, request.Password);
            if (!result) return BadRequest("No se pudo crear el usuario");
            return Ok(usuario);
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> Update(string id, [FromBody] UsuarioUpdateRequest request)
        {
            var usuario = await _usuarioService.GetByIdAsync(id);
            if (usuario == null) return NotFound();
            usuario.NombreCompleto = request.NombreCompleto;
            usuario.FechaNacimiento = request.FechaNacimiento;
            var result = await _usuarioService.UpdateAsync(usuario);
            if (!result) return BadRequest("No se pudo actualizar el usuario");
            return Ok(usuario);
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(string id)
        {
            var result = await _usuarioService.DeleteAsync(id);
            if (!result) return BadRequest("No se pudo eliminar el usuario");
            return Ok();
        }

        [HttpPost("{id}/roles")]
        public async Task<IActionResult> AssignRole(string id, [FromBody] RoleAssignRequest request)
        {
            var usuario = await _usuarioService.GetByIdAsync(id);
            if (usuario == null) return NotFound();
            var result = await _usuarioService.AssignRoleAsync(usuario, request.Role);
            if (!result) return BadRequest("No se pudo asignar el rol");
            return Ok();
        }

        [HttpGet("{id}/roles")]
        public async Task<IActionResult> GetRoles(string id)
        {
            var usuario = await _usuarioService.GetByIdAsync(id);
            if (usuario == null) return NotFound();
            var roles = await _usuarioService.GetRolesAsync(usuario);
            return Ok(roles);
        }
    }

    public class UsuarioCreateRequest
    {
    public string UserName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
        public string? NombreCompleto { get; set; }
        public DateTime? FechaNacimiento { get; set; }
    }

    public class UsuarioUpdateRequest
    {
        public string? NombreCompleto { get; set; }
        public DateTime? FechaNacimiento { get; set; }
    }

    public class RoleAssignRequest
    {
    public string Role { get; set; } = string.Empty;
    }
}
