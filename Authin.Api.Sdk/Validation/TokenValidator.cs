using Authin.Api.Sdk.Model;
using Jose;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace Authin.Api.Sdk.Validation
{
    public class TokenValidator
    {
        public static JObject Validate(string token, Jwks jwks, string issuer, string audience)
        {
            RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
            cryptoServiceProvider.ImportParameters(new RSAParameters()
            {
                Modulus = TokenValidator.FromBase64Url(jwks.Keys[0].Modulus),
                Exponent = TokenValidator.FromBase64Url(jwks.Keys[0].Exponent)
            });
            string json;
            try
            {
                json = JWT.Decode(token, (object)cryptoServiceProvider);
            }
            catch (Exception ex)
            {
                throw new TokenValidationException("Invalid signature.", ex);
            }
            var  claims = JObject.Parse(json);

            //Ignore other validations in case of refresh token
            if (claims["token_type"].ToString().Equals("refresh_token", StringComparison.OrdinalIgnoreCase))
                return claims;

            if (!claims.Properties().Any(c => c.Name.Equals("iss")) || !claims["iss"].ToString().Equals(issuer, StringComparison.OrdinalIgnoreCase))
                throw new TokenValidationException("Invalid issuer.");

            if (!claims.Properties().Any(c => c.Name.Equals("aud")) || !claims["aud"].ToString().Equals(audience, StringComparison.OrdinalIgnoreCase))
                throw new TokenValidationException("Invalid audience.");

            double totalSeconds = DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
            if (!claims.Properties().Any(c => c.Name.Equals("exp")) || long.Parse(claims["exp"].ToString()) <= totalSeconds)
                throw new TokenValidationException("Expired token.");

            return claims;
        }

        private static byte[] FromBase64Url(string base64Url)
        {
            return Convert
                .FromBase64String((base64Url.Length % 4 == 0  ? base64Url : base64Url + "====".Substring(base64Url.Length % 4))
                .Replace("_", "/")
                .Replace("-", "+"));
        }
    }
}
