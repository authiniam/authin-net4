using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Authin.Api.Sdk.Model;
using Newtonsoft.Json;

namespace Authin.Api.Sdk.Request
{
    public class RefreshTokenRequest : IExecutable<TokenResponse>
    {
        private RefreshTokenRequest()
        {
        }

        public string BaseUrl { get; private set; }
        public string AccessToken { get; private set; }
        public string GrantType { get; private set; }
        public string RefreshToken { get; private set; }
        public List<string> Scopes { get; private set; }
        public string ClientId { get; private set; }
        public string ClientSecret { get; private set; }

        public static Builder GetBuilder()
        {
            return new Builder();
        }

        public class Builder
        {
            private string _baseUrl;
            private string _grantType;
            private string _accessToken;
            private string _refreshToken;
            private List<string> _scopes;
            private string _clientId;
            private string _clientSecret;

            public Builder SetBaseUrl(string baseUrl)
            {
                _baseUrl = baseUrl;
                return this;
            }

            public Builder SetAccessToken(string accessToken)
            {
                _accessToken = accessToken;
                return this;
            }

            public Builder SetGrantType(string grantType)
            {
                _grantType = grantType;
                return this;
            }

            public Builder SetRefreshToken(string refreshToken)
            {
                _refreshToken = refreshToken;
                return this;
            }

            public Builder SetScopes(List<string> scopes)
            {
                _scopes = scopes;
                return this;
            }

            public Builder SetClientId(string clientId)
            {
                _clientId = clientId;
                return this;
            }

            public Builder SetClientSecret(string clientSecret)
            {
                _clientSecret = clientSecret;
                return this;
            }

            public RefreshTokenRequest Build()
            {
                _baseUrl = _baseUrl ?? System.Configuration.ConfigurationManager.AppSettings["BaseUrl"];
                if (string.IsNullOrEmpty(_baseUrl))
                    throw new ArgumentException("BaseUrl is a required field");

                if (string.IsNullOrEmpty(_accessToken))
                    throw new ArgumentException("AccessToken is a required field");

                if (string.IsNullOrEmpty(_grantType))
                    throw new ArgumentException("GrantType is a required field");

                if (string.IsNullOrEmpty(_refreshToken))
                    throw new ArgumentException("RefreshToken is a required field");

                if (_scopes == null)
                    throw new ArgumentException("Scopes is a required field");

                if (string.IsNullOrEmpty(_clientId))
                    throw new ArgumentException("ClientId is a required field");

                if (string.IsNullOrEmpty(_clientSecret))
                    throw new ArgumentException("ClientSecret is a required field");

                return new RefreshTokenRequest
                {
                    BaseUrl = _baseUrl,
                    AccessToken = _accessToken,
                    GrantType = _grantType,
                    RefreshToken = _refreshToken,
                    Scopes = _scopes,
                    ClientId = _clientId,
                    ClientSecret = _clientSecret,
                };
            }
        }

        public Task<TokenResponse> Execute()
        {
            return new Task<TokenResponse>(() =>
            {
                var tokenEndpoint = new Uri(new Uri(BaseUrl), "/api/v1/oauth/token");

                var request = (HttpWebRequest) WebRequest.Create(tokenEndpoint);
                request.Method = "POST";
                request.ContentType = "application/x-www-form-urlencoded";
                var requestStream = request.GetRequestStream();
                var tokenRequestBody =
                    $"grant_type={GrantType}" +
                    $"&refresh_token={RefreshToken}" +
                    $"&scope={string.Join(" ", Scopes)}" +
                    $"&client_id={ClientId}" +
                    $"&client_secret={ClientSecret}";

                var postArray = Encoding.ASCII.GetBytes(tokenRequestBody);
                requestStream.Write(postArray, 0, postArray.Length);
                requestStream.Close();

                string content;
                using (var response = (HttpWebResponse) request.GetResponse())
                {
                    using (var stream = response.GetResponseStream())
                    {
                        using (var sr = new StreamReader(stream))
                        {
                            content = sr.ReadToEnd();
                        }
                    }
                }

                return JsonConvert.DeserializeObject<TokenResponse>(content);
            });
        }
    }
}