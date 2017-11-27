using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace OidcWebApp
{
    public class Startup
    {
        private readonly IHostingEnvironment _env;
        private readonly IConfigurationRoot _configuration;

        public Startup(IHostingEnvironment env)
        {
            _env = env;
            var builder = new ConfigurationBuilder()
               .SetBasePath(_env.ContentRootPath)
               .AddJsonFile("config.json");

            _configuration = builder.Build();

            // Fix default OIDC claims mapping
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
        }

        public void ConfigureServices(IServiceCollection services)
        {

            services.AddAuthentication("oidc")
                .AddCookie()
                .AddOpenIdConnect("oidc", options =>
                {
                    options.ProtocolValidator = new OpenIdConnectProtocolValidator
                    {
                        //RequireNonce = false,
                        //RequireState = false
                    };

                    options.AuthenticationMethod = OpenIdConnectRedirectBehavior.RedirectGet;

                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                    options.Authority = _configuration["oidc:authority"];
                    options.ClientId = _configuration["oidc:client_id"];
                    options.ClientSecret = _configuration["oidc:client_secret"];
                    options.Scope.Add("openid");
                    options.Scope.Add("profile");

                    options.CallbackPath = "/redirect.html";

                    options.ResponseType = "code id_token";
                    options.SaveTokens = true;
                    options.GetClaimsFromUserInfoEndpoint = true;

                    if (_env.IsDevelopment() && !string.IsNullOrEmpty(_configuration["oidc:proxy"]))
                    {
                        options.RequireHttpsMetadata = false;
                        options.BackchannelHttpHandler = new HttpClientHandler()
                        {
                            Proxy = new WebProxy(_configuration["oidc:proxy"])
                            {
                                Credentials = CredentialCache.DefaultNetworkCredentials
                            }
                        };
                    }

                    options.Events = new OpenIdConnectEvents
                    {
                        OnMessageReceived = x =>
                        {
                            // state is present
                            return Task.CompletedTask;
                        },
                        OnTokenValidated = x =>
                        {
                            // state is missing
                            return Task.CompletedTask;
                        },

                    };
                });
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseAuthentication();

            app.Run(async (context) =>
            {
                var result = await context.AuthenticateAsync();
                if (!result.Succeeded)
                {
                    await context.ChallengeAsync();
                    return;
                }

                await context.Response.WriteAsync("Hello World!");
            });
        }
    }
}
