using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using refactored_umbrella.Data;
using refactored_umbrella.Models;
using System.Security.Claims;

namespace refactored_umbrella.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ClaimsSetupController : ControllerBase
    {
        private readonly AuthDbContext _authDbContext;
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<SetupController> _logger;

        public ClaimsSetupController(
            AuthDbContext authDbContext,
            UserManager<User> userManager,
            RoleManager<IdentityRole> roleManager,
            ILogger<SetupController> logger)
        {
            _authDbContext = authDbContext;
            _userManager = userManager;
            _roleManager = roleManager;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> GetAllClaims(string email)
        {
            // Check if the user exist
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                _logger.LogInformation($"The user with the {email} does not exist");
                return BadRequest(new
                {
                    error = $"The user with the {email} does not exist"
                });
            }

            var claims = _userManager.GetClaimsAsync(user);
            return Ok(claims.Result);
        }

        [HttpPost]
        [Route("AddClaimsToUser")]
        public async Task<IActionResult> AddClaimsToUser(string email, string claimName, string claimValue)
        {
            // Check if the user exist
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                _logger.LogInformation($"The user with the {email} does not exist");
                return BadRequest(new
                {
                    error = $"The user with the {email} does not exist"
                });
            }

            var userClaim = new Claim(claimName, claimValue);

            var result = await _userManager.AddClaimAsync(user, userClaim);

            if (result.Succeeded)
            {
                return Ok(new
                {
                    result = $"User {user.Email} has a claim {claimName} added to them"
                });
            }

            return BadRequest(new
            {
                error = $"Unable to add claim {claimName} to the user {user.Email}"
            });
        }
    }
}
