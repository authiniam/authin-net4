using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Authin.Api.Sdk.Model;
using Newtonsoft.Json;

namespace Authin.Api.Sdk.Request
{
    public class JwksRequest : IExecutable<Jwks>
    {
        public string BaseUrl { get; private set; }

        private JwksRequest()
        {
        }

        public static Builder GetBuilder()
        {
            return new Builder();
        }

        public class Builder
        {
            private string _baseUrl;

            public Builder SetBaseUrl(string baseUrl)
            {
                _baseUrl = baseUrl;
                return this;
            }

            public JwksRequest Build()
            {
                _baseUrl = _baseUrl ?? System.Configuration.ConfigurationManager.AppSettings["BaseUrl"];
                if (string.IsNullOrEmpty(_baseUrl))
                    throw new ArgumentException("BaseUrl is a required field");

                return new JwksRequest
                {
                    BaseUrl = _baseUrl
                };
            }
        }

        public Task<Jwks> Execute()
        {
            return new Task<Jwks>(() =>
            {
                var keysEndpoint = new Uri(new Uri(BaseUrl), "/api/v1/keys");

                var request = (HttpWebRequest)WebRequest.Create(keysEndpoint);
                request.Method = "GET";

                string content;
                using (var response = (HttpWebResponse)request.GetResponse())
                {
                    using (var stream = response.GetResponseStream())
                    {
                        using (var sr = new StreamReader(stream))
                        {
                            content = sr.ReadToEnd();
                        }
                    }
                }

                return JsonConvert.DeserializeObject<Jwks>(content);
            });
        }
    }
}
