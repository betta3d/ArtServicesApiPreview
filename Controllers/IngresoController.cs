using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;

namespace ArtServiceApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class IngresoController : ControllerBase
    {
        // Datos mock in-memory (simulando BD)
        private static List<ServicioMock> _servicios = new List<ServicioMock>();
        private static List<VehiculoMock> _vehiculos = new List<VehiculoMock>
        {
            new VehiculoMock { Patente = "ABCD12", Modelo = "Toyota Corolla" },
            new VehiculoMock { Patente = "EFGH34", Modelo = "Honda Civic" }
        };
        private static List<SelectOption> _unidades = new List<SelectOption>
        {
            new SelectOption { Value = 1, Text = "Unidad 1" },
            new SelectOption { Value = 2, Text = "Unidad 2" }
        };
        private static List<SelectOption> _tiposServicioServicio = new List<SelectOption>
        {
            new SelectOption { Value = 1, Text = "Lavado" },
            new SelectOption { Value = 2, Text = "Otro Servicio" }
        };
        private static List<SelectOption> _tiposServicioMantencion = new List<SelectOption>
        {
            new SelectOption { Value = 5, Text = "Mantención" },
            new SelectOption { Value = 6, Text = "Mantención-Lavado" }
        };
        private static List<SelectOption> _tiposSegmento = new List<SelectOption>
        {
            new SelectOption { Value = 1, Text = "Segmento A" },
            new SelectOption { Value = 2, Text = "Segmento B" }
        };

        [HttpPost("ListarUnidadesSelect")]
        public IActionResult ListarUnidadesSelect([FromBody] TipoRequest request)
        {
            return Ok(new { JsonRetono = _unidades }); // Mock
        }

        [HttpPost("ListarTipoServicioSelect")]
        public IActionResult ListarTipoServicioSelect([FromBody] TipoRequest request)
        {
            var lista = request.tipo.ToLower() == "servicio" ? _tiposServicioServicio : _tiposServicioMantencion;
            return Ok(new { JsonRetono = lista });
        }

        [HttpPost("ListarTipoSegmentoSelect")]
        public IActionResult ListarTipoSegmentoSelect([FromBody] TipoRequest request)
        {
            return Ok(new { JsonRetono = _tiposSegmento });
        }

        [HttpPost("AutoCompletePatente")]
        public IActionResult AutoCompletePatente([FromBody] PrefixRequest request)
        {
            var resultados = _vehiculos
                .Where(v => v.Patente.StartsWith(request.prefix.ToUpper()))
                .Select(v => new { label = v.Patente, val = v.Modelo })
                .ToList();
            return Ok(new { JsonRetono = resultados });
        }

        [HttpPost("IngresarServicio")]
        public IActionResult IngresarServicio([FromBody] IngresoRequest request)
        {
            var ingreso = JsonConvert.DeserializeObject<IngresoDto>(request.json);
            // Simula lógica de guardado
            if (_servicios.Any(s => s.Patente == ingreso.Patente && s.FechaServicio == ingreso.Fecha.ToShortDateString()) && ingreso.IngresoConfirmado == 0)
            {
                return Ok(new { DebeConfirmar = true, Mensaje = new { Message = "Este vehículo ya fue ingresado hoy. ¿Está seguro?" } });
            }

            _servicios.Add(new ServicioMock
            {
                Id = _servicios.Count + 1,
                Organizacion = "Org Mock",
                Segmento = "Seg Mock",
                Unidad = "Uni Mock",
                TipoServicio = "Tipo Mock",
                Patente = ingreso.Patente,
                Modelo = ingreso.Modelo,
                FechaServicio = ingreso.Fecha.ToShortDateString(),
                FechaIngreso = DateTime.Now.ToShortDateString(),
                Comentarios = ingreso.Comentarios
            });

            return Ok(new { EsError = false, Mensaje = new { Message = "Servicio Ingresado correctamente." } });
        }

        [HttpGet("ListarIngresadosHoy")]
        public IActionResult ListarIngresadosHoy(string tipo)
        {
            // Mock: Devuelve todos por ahora, filtrado por tipo si es necesario
            return Ok(_servicios);
        }
    }

    // Clases mock
    public class TipoRequest { public string tipo { get; set; } }
    public class PrefixRequest { public string prefix { get; set; } }
    public class IngresoRequest { public string json { get; set; } }
    public class SelectOption { public int Value { get; set; } public string Text { get; set; } }
    public class VehiculoMock { public string Patente { get; set; } public string Modelo { get; set; } }
    public class ServicioMock
    {
        public int Id { get; set; }
        public string Organizacion { get; set; }
        public string Segmento { get; set; }
        public string Unidad { get; set; }
        public string TipoServicio { get; set; }
        public string Patente { get; set; }
        public string Modelo { get; set; }
        public string FechaServicio { get; set; }
        public string FechaIngreso { get; set; }
        public string Comentarios { get; set; }
    }
    public class IngresoDto
    {
        public int TipoUnidadId { get; set; }
        public int TipoServicioId { get; set; }
        public int TipoSegmentoId { get; set; }
        public string Modelo { get; set; }
        public string Patente { get; set; }
        public bool LavadoMotor { get; set; }
        public string Comentarios { get; set; }
        public DateTime Fecha { get; set; }
        public int IngresoConfirmado { get; set; }
    }
}