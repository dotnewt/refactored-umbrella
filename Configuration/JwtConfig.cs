﻿namespace refactored_umbrella.Configuration
{
    public class JwtConfig
    {
        public string Key { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public string Subject { get; set; }
        public int Expire { get; set; }
    }
}
