namespace refactored_umbrella.Models.DTO
{
    public class AuthResponse
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public bool IsSuccess { get; set; } = true;
        public List<string> Errors { get; set; }
    }
}
