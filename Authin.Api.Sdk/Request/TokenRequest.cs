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
    public class TokenRequest : IExecutable<TokenResponse>
    {
        private TokenRequest()
        {
        }

        public string BaseUrl { get; private set; }
        public string Code { get; protected set; }
        public string RedirectUri { get; private set; }
        public string ClientId { get; private set; }
        public string ClientSecret { get; private set; }
        public string GrantType { get; private set; }

        public static Builder GetBuilder()
        {
            return new Builder();
        }

        public class Builder
        {
            private string _baseUrl;
            private string _code;
            private string _redirectUri;
            private string _clientId;
            private string _clientSecret;
            private string _grantType;

            public Builder SetBaseUrl(string baseUrl)
            {
                _baseUrl = baseUrl;
                return this;
            }

            public Builder SetCode(string code)
            {
                _code = code;
                return this;
            }

            public Builder SetRedirectUri(string redirectUri)
            {
                _redirectUri = redirectUri;
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

            public Builder SetGrantType(string grantType)
            {
                _grantType = grantType;
                return this;
            }

            public TokenRequest Build()
            {
                _baseUrl = _baseUrl ?? System.Configuration.ConfigurationManager.AppSettings["BaseUrl"];
                if (string.IsNullOrEmpty(_baseUrl))
                    throw new ArgumentException("BaseUrl is a required field");

                if (string.IsNullOrEmpty(_code))
                    throw new ArgumentException("Code is a required field");

                if (string.IsNullOrEmpty(_redirectUri))
                    throw new ArgumentException("RedirectUri is a required field");

                if (string.IsNullOrEmpty(_clientId))
                    throw new ArgumentException("ClientId is a required field");

                if (string.IsNullOrEmpty(_clientSecret))
                    throw new ArgumentException("ClientSecret is a required field");

                if (string.IsNullOrEmpty(_grantType))
                    throw new ArgumentException("GrantType is a required field");

                return new TokenRequest
                {
                    BaseUrl = _baseUrl,
                    Code = _code,
                    RedirectUri = _redirectUri,
                    ClientId = _clientId,
                    ClientSecret = _clientSecret,
                    GrantType = _grantType
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
                    $"code={Code}" +
                    $"&redirect_uri={RedirectUri}" +
                    $"&client_id={ClientId}" +
                    $"&client_secret={ClientSecret}" +
                    $"&grant_type={GrantType}";

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