﻿// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using System.Globalization;
using Microsoft.Azure.Common.Authentication.Models;
using Microsoft.Azure.Common.Authentication.Properties;
using System;
using System.Linq;
using System.Security;
using Hyak.Common;
using Microsoft.Rest;
using Microsoft.Rest.Azure.Authentication;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Microsoft.Azure.Common.Authentication.Factories
{
    public class AuthenticationFactory : IAuthenticationFactory
    {
        public const string CommonAdTenant = "Common";

        public AuthenticationFactory()
        {
        }

        internal ITokenProvider TokenProvider { get; set; }

        public ITokenProvider Login(
            AzureAccount account, 
            AzureEnvironment environment, 
            string tenant, 
            ShowDialog promptBehavior,
            TokenCache cache,
            AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId)
        {
            if (environment == null)
            {
                environment = AzureEnvironment.PublicEnvironments["AzureCloud"];
            }

            var adEnvironment = new ActiveDirectoryEnvironment
            {
                AuthenticationEndpoint = environment.GetEndpointAsUri(AzureEnvironment.Endpoint.ActiveDirectory),
                TokenAudience = environment.GetEndpointAsUri(resourceId),
                ValidateAuthority = !environment.OnPremise
            };

            if (string.IsNullOrWhiteSpace(tenant))
            {
                tenant = CommonAdTenant;
            }

            if (TokenProvider != null)
            {
                return TokenProvider;
            }

            if (account == null || (account.Type == AzureAccount.AccountType.User))
            {
                return new ActiveDirectoryUserTokenProvider(AdalConfiguration.PowerShellClientId, tenant, 
                    adEnvironment, AdalConfiguration.PowerShellRedirectUri, 
                    new ActiveDirectoryParameters
                    {
                        OwnerWindow = new ConsoleParentWindow(), 
                        PromptBehavior = PromptBehavior.Always,
                        TokenCache = cache
                    } );
            }

            throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, 
                "Could not log in with given information (account id: '{0}', account type : '{1}', tenant/domain: '{2}'", 
                account.Id, account.Type, tenant));
            
        }

        public ITokenProvider Login(AzureAccount account, AzureEnvironment environment, string tenant, ShowDialog promptBehavior, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId)
        {
            return Login(account, environment, tenant, promptBehavior, AzureSession.TokenCache, resourceId);
        }

        public ITokenProvider Login(AzureAccount account, AzureEnvironment environment, string tenant, SecureString password, TokenCache cache, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId)
        {
            if (account == null)
            {
                throw new ArgumentNullException("account");
            }

            if (account.Id == null)
            {
                throw new ArgumentOutOfRangeException("account id cannot be null");
            }

            if (environment == null)
            {
                environment = AzureEnvironment.PublicEnvironments["AzureCloud"];
            }

            if (string.IsNullOrWhiteSpace(tenant))
            {
                tenant = CommonAdTenant;
            }

            if (TokenProvider != null)
            {
                return TokenProvider;
            }

            var adEnvironment = new ActiveDirectoryEnvironment
            {
                AuthenticationEndpoint = environment.GetEndpointAsUri(AzureEnvironment.Endpoint.ActiveDirectory),
                TokenAudience = environment.GetEndpointAsUri(resourceId),
                ValidateAuthority = !environment.OnPremise
            };

            var adSettings = new ActiveDirectoryParameters
            {
                PromptBehavior = PromptBehavior.Never,
                TokenCache = cache
            };

            if (account.Type == AzureAccount.AccountType.User)
            {
                return new ActiveDirectoryUserTokenProvider(AdalConfiguration.PowerShellClientId, tenant, 
                    account.Id, TokenProviderUtilities.ConvertToString(password), adEnvironment, adSettings);
            }

            if (account.Type == AzureAccount.AccountType.ServicePrincipal)
            {
                return new ApplicationCredentialStoreTokenProvider(account.Id, tenant, 
                    TokenProviderUtilities.ConvertToString(password), adEnvironment, cache);
            }

            throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, 
                "Could not log in with given information (account id: '{0}', account type : '{1}', tenant/domain: '{2}') and the given password.", 
                account.Id, account.Type, tenant));
        }

        public ITokenProvider Login(AzureAccount account, AzureEnvironment environment, string tenant, SecureString password, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId)
        {
            return Login(account, environment, tenant, password, AzureSession.TokenCache, resourceId);
        }

        public ITokenProvider Authenticate(AzureAccount account, AzureEnvironment environment, string tenant, TokenCache cache, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId)
        {
            if (account == null)
            {
                throw new ArgumentNullException("account");
            }

            if (account.Id == null)
            {
                throw new ArgumentOutOfRangeException("account id cannot be null");
            }

            if (environment == null)
            {
                environment = AzureEnvironment.PublicEnvironments["AzureCloud"];
            }

            if (string.IsNullOrWhiteSpace(tenant))
            {
                tenant = CommonAdTenant;
            }

            if (TokenProvider != null)
            {
                return TokenProvider;
            }

            var adEnvironment = new ActiveDirectoryEnvironment
            {
                AuthenticationEndpoint = environment.GetEndpointAsUri(AzureEnvironment.Endpoint.ActiveDirectory),
                TokenAudience = environment.GetEndpointAsUri(resourceId),
                ValidateAuthority = !environment.OnPremise
            };

            var adSettings = new ActiveDirectoryParameters
            {
                PromptBehavior = PromptBehavior.Never,
                TokenCache = cache
            };

            if (account.Type == AzureAccount.AccountType.User)
            {
                return new ActiveDirectoryUserTokenProvider(AdalConfiguration.PowerShellClientId, tenant, 
                    account.Id, null, adEnvironment, adSettings);
            }

            if (account.Type == AzureAccount.AccountType.ServicePrincipal)
            {
                return ApplicationCredentialStoreTokenProvider.GetProviderFromCredStore(account.Id, tenant, 
                    adEnvironment, cache);
            }

            throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, 
                "Could not find existing credentials with given information (account id: '{0}', account type : '{1}', tenant/domain: '{2}') and the given password.", 
                account.Id, account.Type, tenant));
        }

        public ITokenProvider Authenticate(AzureAccount account, AzureEnvironment environment, string tenant, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId)
        {
            return Authenticate(account, environment, tenant, AzureSession.TokenCache, resourceId);
        }

        public SubscriptionCloudCredentials GetSubscriptionCloudCredentials(AzureContext context, TokenCache cache, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId)
        {
            if (context.Subscription == null)
            {
                throw new ApplicationException(Resources.InvalidDefaultSubscription);
            }
            
            if (context.Account == null)
            {
                throw new ArgumentException(Resources.AccountNotFound);
            }

            if (context.Account.Type == AzureAccount.AccountType.Certificate)
            {
                var certificate = AzureSession.DataStore.GetCertificate(context.Account.Id);
                return new CertificateCloudCredentials(context.Subscription.Id.ToString(), certificate);
            }

            if (context.Account.Type == AzureAccount.AccountType.AccessToken)
            {
                return new TokenCloudCredentials(context.Subscription.Id.ToString(), context.Account.GetProperty(AzureAccount.Property.AccessToken));
            }

            var tenant = context.Subscription.GetPropertyAsArray(AzureSubscription.Property.Tenants)
                  .Intersect(context.Account.GetPropertyAsArray(AzureAccount.Property.Tenants))
                  .FirstOrDefault();

            if (tenant == null)
            {
                throw new ArgumentException(Resources.TenantNotFound);
            }

            try
            {
                TracingAdapter.Information(Resources.UPNAuthenticationTrace, 
                    context.Account.Id, context.Environment.Name, tenant);
                var provider = Authenticate(context.Account, context.Environment, 
                    tenant, cache, resourceId);
                return new AccessTokenCredential(context.Subscription.Id, provider);
            }
            catch (Exception ex)
            {
                 TracingAdapter.Information(Resources.AdalAuthException, ex.Message);
                throw new ArgumentException(Resources.InvalidSubscriptionState, ex);
            }
        }

        public ServiceClientCredentials GetServiceClientCredentials(AzureContext context, TokenCache cache, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId)
        {
            if (context.Subscription == null)
            {
                throw new ApplicationException(Resources.InvalidDefaultSubscription);
            }

            if (context.Account == null)
            {
                throw new ArgumentException(Resources.AccountNotFound);
            }

            if (context.Account.Type == AzureAccount.AccountType.Certificate)
            {
                throw new NotSupportedException(AzureAccount.AccountType.Certificate.ToString());
            }

            if (context.Account.Type == AzureAccount.AccountType.AccessToken)
            {
                return new TokenCredentials(context.Account.GetProperty(AzureAccount.Property.AccessToken));
            }

            var tenant = context.Subscription.GetPropertyAsArray(AzureSubscription.Property.Tenants)
                  .Intersect(context.Account.GetPropertyAsArray(AzureAccount.Property.Tenants))
                  .FirstOrDefault();

            if (tenant == null)
            {
                throw new ArgumentException(Resources.TenantNotFound);
            }

            try
            {
                TracingAdapter.Information(Resources.UPNAuthenticationTrace,
                    context.Account.Id, context.Environment.Name, tenant);


                var env = new ActiveDirectoryEnvironment
                {
                    AuthenticationEndpoint = context.Environment.GetEndpointAsUri(AzureEnvironment.Endpoint.ActiveDirectory),
                    TokenAudience = context.Environment.GetEndpointAsUri(AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId),
                    ValidateAuthority = !context.Environment.OnPremise
                };

                var provider = Authenticate(context.Account, context.Environment, tenant, cache, resourceId);
                return new TokenCredentials(provider);
            }
            catch (Exception ex)
            {
                TracingAdapter.Information(Resources.AdalAuthException, ex.Message);
                throw new ArgumentException(Resources.InvalidSubscriptionState, ex);
            }
        }


        public SubscriptionCloudCredentials GetSubscriptionCloudCredentials(AzureContext context, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId)
        {
            return GetSubscriptionCloudCredentials(context, AzureSession.TokenCache, resourceId);
        }

        public ServiceClientCredentials GetServiceClientCredentials(AzureContext context, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId)
        {
            return GetServiceClientCredentials(context, AzureSession.TokenCache, resourceId);
        }
    }
}
