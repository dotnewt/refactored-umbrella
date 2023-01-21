using System.ComponentModel.DataAnnotations;

namespace refactored_umbrella.Models.DTO
{
    public class LoginRequest
    {
        [Required]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
