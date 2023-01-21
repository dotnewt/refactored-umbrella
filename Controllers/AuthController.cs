using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using refactored_umbrella.Configuration;
using refactored_umbrella.Data;
using refactored_umbrella.Models;
using refactored_umbrella.Models.DTO;

namespace refactored_umbrella.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private JwtConfig _jwtConfig;
        private readonly UserManager<User> _userManager;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly AuthDbContext _authDbContext;

        public AuthController(
            IOptions<JwtConfig> jwtConfig,
            UserManager<User> userManager,
            TokenValidationParameters tokenValidationParameters,
            AuthDbContext authDbContext)
        {
            _jwtConfig = jwtConfig.Value;
            _userManager = userManager;
            _tokenValidationParameters = tokenValidationParameters;
            _authDbContext = authDbContext;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login(LoginRequest loginRequest)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await _userManager.FindByEmailAsync(loginRequest.Email);
            var isAuthorized = user != null && await _userManager.CheckPasswordAsync(user, loginRequest.Password);

            if(isAuthorized)
            {
                var authResponse = await GetTokens(user);

                return Ok(authResponse);
            }
            else
            {
                return Unauthorized("Invalid credentials");
            }
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register(RegisterRequest registerRequest)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            bool isEmailAlreadyRegistered = await _userManager.FindByEmailAsync(registerRequest.Email) != null;
            bool isUserNameAlreadyRegistered = await _userManager.FindByNameAsync(registerRequest.UserName) != null;
            if (isEmailAlreadyRegistered)
            {
                return Conflict($"UserName Id {registerRequest.UserName} is already registered");
            }
            if (isEmailAlreadyRegistered)
            {
                return Conflict($"Email Id {registerRequest.Email} is already registered");
            }

            var newUser = new User
            {
                Email = registerRequest.Email,
                FirstName = registerRequest.FirstName,
                LastName = registerRequest.LastName,
                UserName = registerRequest.UserName
            };

            var result = await _userManager.CreateAsync(newUser, registerRequest.Password);

            if (result.Succeeded)
            {
                var authResponse = await GetTokens(newUser);
                return Ok(authResponse);
            }
            else
            {
                return StatusCode(500, result.Errors.Select(e => new { Msg = e.Code, Desc = e.Description }).ToList());
            }
        }

        [HttpPost]
        [Route("refresh")]
        public async Task<IActionResult> Refresh(RefreshRequest refreshRequest)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await VerifyAndGenerateToken(refreshRequest);

            if(result == null)
            {
                return BadRequest(new AuthResponse()
                {
                    IsSuccess = false,
                    Errors = new List<string>()
                    {
                        "Invalid payload"
                    }
                });
            }

            return Ok(result);
        }

        private async Task<AuthResponse> VerifyAndGenerateToken(RefreshRequest refreshRequest)
        {
            var JwtTokenhandler = new JwtSecurityTokenHandler();

            try
            {
                #region Validation

                // Validation 1 - Validation JWT token format
                var tokenInVerification = JwtTokenhandler.ValidateToken(refreshRequest.AccessToken, _tokenValidationParameters, out var validatedToken);

                // Validationb 2 - Validate encryption alg
                if(validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);

                    if (result == false)
                    {
                        return null;
                    }
                }

                // Validation 3 - Validate expiry date
                var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

                var expirtyDate = UnixTimeStampToDateTime(utcExpiryDate);
                
                if(expirtyDate > DateTime.Now)
                {
                    return new AuthResponse()
                    {
                        IsSuccess = false,
                        Errors = new List<string>()
                        {
                            $"Token has not yet expired - \n {expirtyDate} - {DateTime.Now}"
                        }
                    };
                }

                // validation 4 - Validate existence of the token
                var storedToken = await _authDbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == refreshRequest.RefreshToken);

                if(storedToken == null)
                {
                    return new AuthResponse()
                    {
                        IsSuccess = false,
                        Errors = new List<string>()
                        {
                            "Token does not exist"
                        }
                    };
                }

                // Validation 5 - Validate if used
                if (storedToken.IsUsed)
                {
                    return new AuthResponse()
                    {
                        IsSuccess = false,
                        Errors = new List<string>()
                        {
                            "Token has been used"
                        }
                    };
                }

                // Validation 6 - Validate if revorked
                if(storedToken.IsRevorked)
                {
                    return new AuthResponse()
                    {
                        IsSuccess = false,
                        Errors = new List<string>()
                        {
                            "Token has been revorked"
                        }
                    };
                }

                // Validation 7 - Validate the ID
                var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

                if(storedToken.JwtId != jti)
                {
                    return new AuthResponse()
                    {
                        IsSuccess = false,
                        Errors = new List<string>()
                        {
                            "Token doesn't match"
                        }
                    };
                }

                #endregion

                // Update current Token
                storedToken.IsUsed= true;
                _authDbContext.RefreshTokens.Update(storedToken);
                await _authDbContext.SaveChangesAsync();

                // Generate a new token
                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
                return await GetTokens(dbUser);
            }
            catch
            {
                return null;
            }
        }

        private DateTime UnixTimeStampToDateTime(long utcExpiryDate)
        {
            var dateTimeVal = new DateTime(1970, 1,1,0,0,0,0, DateTimeKind.Utc);
            dateTimeVal = dateTimeVal.AddSeconds(utcExpiryDate).ToLocalTime();
            return dateTimeVal;
        }

        private async Task<AuthResponse> GetTokens(User user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, _jwtConfig.Subject),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToString()),
                new Claim("Id", user.Id),
                new Claim("Email", user.Email),
                new Claim("UserName", user.UserName)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfig.Key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                _jwtConfig.Issuer,
                _jwtConfig.Audience,
                claims,
                expires: DateTime.Now.AddSeconds(Convert.ToDouble(_jwtConfig.Expire)),
                signingCredentials: creds
                );

            var tokenStr = new JwtSecurityTokenHandler().WriteToken(token);
            var refreshToken = new RefreshToken()
            {
                JwtId = token.Id,
                IsUsed = false,
                IsRevorked = false,
                UserId = user.Id,
                AddedDate = DateTime.Now,
                ExpiryDate = DateTime.Now.AddHours(1),
                Token = RandomString(35) +  Guid.NewGuid().ToString(),
            };
            
            await _authDbContext.RefreshTokens.AddAsync(refreshToken);
            await _authDbContext.SaveChangesAsync();

            var authResponse = new AuthResponse { 
                AccessToken= tokenStr, 
                RefreshToken = refreshToken.Token 
            };
            return await Task.FromResult(authResponse);
        }

        private string RandomString(int length)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new  string(Enumerable.Repeat(chars, length)
                .Select(x => x[random.Next(x.Length)]).ToArray());
        }
    }
}
