using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using refactored_umbrella.Models;

namespace refactored_umbrella.Data
{
    public class AuthDbContext: IdentityDbContext<User>
    {
        public AuthDbContext(DbContextOptions<AuthDbContext> options)
            :base(options)
        {

        }

        public DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}
