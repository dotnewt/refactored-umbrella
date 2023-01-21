using Microsoft.AspNetCore.Identity;

namespace refactored_umbrella.Models
{
    public class User: IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public DateTime? DateOfBirth { get; set; }
        public string? Country { get; set; }
        public string? City { get; set; }
    }
}

