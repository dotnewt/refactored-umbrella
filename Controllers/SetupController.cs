using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using refactored_umbrella.Data;
using refactored_umbrella.Models;
using System.Xml.Linq;

namespace refactored_umbrella.Controllers
{
    [Route("api/[controller]")]     // api/setup
    [ApiController]
    [Authorize(Roles = "AppUser")]
    public class SetupController : ControllerBase
    {
        private readonly AuthDbContext _authDbContext;
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<SetupController> _logger;

        public SetupController(
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
        public IActionResult GetAllRoles()
        {
            var roles = _roleManager.Roles.ToList();
            return Ok(roles);
        }

        [HttpPost]
        public async Task<IActionResult> CreateRole(string name)
        {
            // Check if the role exist
            var roleExist = await _roleManager.RoleExistsAsync(name);
            
            if (roleExist)
            {
                return BadRequest(new { error = "Role already exist" });
            }

            var roleResult = await _roleManager.CreateAsync(new IdentityRole { Name = name });

            // We need check if the role has been added successfully
            if (roleResult.Succeeded)
            {
                _logger.LogInformation($"The Role {name} has been added successfully");
                return Ok(new
                {
                    result = $"The role {name} has been added successfully"
                });
            }
            else
            {
                _logger.LogInformation($"The Role {name} has not been added successfully");
                return BadRequest(new
                {
                    result = $"The role {name} has not been added successfully"
                });
            }
        }

        [HttpGet]
        [Route("GetAllUsers")]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _userManager.Users.ToListAsync();
            return Ok(users);
        }

        [HttpPost]
        [Route("AddUserToRole")]
        public async Task<IActionResult> AddUserToRole(string email, string roleName)
        {
            // Check if the user exist
            var user = await _userManager.FindByEmailAsync(email);

            if(user == null)
            {
                _logger.LogInformation($"The user with the {email} does not exist");
                return BadRequest(new
                {
                    error = $"The user with the {email} does not exist"
                });
            }

            // Check if the role exist
            var roleExist = await _roleManager.RoleExistsAsync(roleName);

            if (!roleExist)
            {
                _logger.LogInformation($"The role {roleName} does not exist");
                return BadRequest(new
                {
                    error = $"The role {roleName} does not exist"
                });
            }

            var result = await _userManager.AddToRoleAsync(user, roleName);

            // Check if the user is assigned to the role  successfully
            if(result.Succeeded)
            {
                return Ok(new
                {
                    result = "Success, user has been added to the role"
                });
            }
            else
            {
                _logger.LogInformation("The user was not abel to be added to the role");
                return BadRequest(new
                {
                    error = "The user was not abel to be added to the role"
                });
            }
        }

        [HttpGet]
        [Route("GetUserRoles")]
        public async Task<IActionResult> GetUserRoles(string email)
        {
            // Check if the email is valid
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                _logger.LogInformation($"The user with the {email} does not exist");
                return BadRequest(new
                {
                    error = $"The user with the {email} does not exist"
                });
            }

            // return the roles
            var roles = await _userManager.GetRolesAsync(user);

            return Ok(roles);
        }

        [HttpDelete]
        [Route("RemoveUserFromRole")]
        public async Task<IActionResult> RemoveUserFromRole(string email, string roleName)
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

            // Check if the role exist
            var roleExist = await _roleManager.RoleExistsAsync(roleName);

            if (!roleExist)
            {
                _logger.LogInformation($"The role {roleName} does not exist");
                return BadRequest(new
                {
                    error = $"The role {roleName} does not exist"
                });
            }

            var result = await _userManager.RemoveFromRoleAsync(user, roleName);
            if (result.Succeeded)
            {
                return Ok(new
                {
                    result = $"User has been removed from role {roleName}"
                });
            }
            else
            {
                _logger.LogInformation($"Unable to remove user {user} from role {roleName}");
                return BadRequest(new
                {
                    error = $"Unable to remove user {user} from role {roleName}"
                });
            }
        }
    }
}
