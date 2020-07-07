using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Authin.Api.Sdk.Model;
using Newtonsoft.Json;

namespace Authin.Api.Sdk.Request
{
    public class UserInfoRequest : IExecutable<UserInfoResponse>
    {
        private UserInfoRequest()
        {
        }

        public string BaseUrl { get; private set; }
        public string AccessToken { get; private set; }
        public Method Method { get; private set; }

        public static Builder GetBuilder()
        {
            return new Builder();
        }

        public class Builder
        {
            private string _baseUrl;
            private string _accessToken;
            private Method _method;

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

            public Builder SetMethod(Method method)
            {
                _method = method;
                return this;
            }

            public UserInfoRequest Build()
            {
                _baseUrl = _baseUrl ?? System.Configuration.ConfigurationManager.AppSettings["BaseUrl"];
                if (string.IsNullOrEmpty(_baseUrl))
                    throw new ArgumentException("BaseUrl is a required field");

                if (string.IsNullOrEmpty(_accessToken))
                    throw new ArgumentException("AccessToken is a required field");

                return new UserInfoRequest
                {
                    BaseUrl = _baseUrl,
                    AccessToken = _accessToken,
                    Method = _method
                };
            }
        }

        public Task<UserInfoResponse> Execute()
        {
            return new Task<UserInfoResponse>(() =>
            {
                var userinfoEndpoint = new Uri(new Uri(BaseUrl), "/api/v1/oauth/userinfo");

                var request = (HttpWebRequest) WebRequest.Create(userinfoEndpoint);
                request.Method = Method == Method.Post ? "POST" : "GET";
                request.Headers.Add(HttpRequestHeader.Authorization, $"Bearer {AccessToken}");

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

                return JsonConvert.DeserializeObject<UserInfoResponse>(content);
            });
        }
    }

    public enum Method
    {
        Get,
        Post
    }
}