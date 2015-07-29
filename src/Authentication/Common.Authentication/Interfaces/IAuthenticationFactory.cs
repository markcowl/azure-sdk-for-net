// ----------------------------------------------------------------------------------
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

using Microsoft.Azure.Common.Authentication.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Rest;
using System.Security;

namespace Microsoft.Azure.Common.Authentication
{
    public interface IAuthenticationFactory
    {
        /// <summary>
        /// Log in using a login prompt. Returns ITokenProvider if authentication succeeds or throws an exception if 
        /// authentication fails.
        /// </summary>
        /// <param name="account">The azure account object</param>
        /// <param name="environment">The azure environment object</param>
        /// <param name="tenant">The AD tenant in most cases should be 'common'</param>
        /// <param name="promptBehavior">The prompt behavior</param>
        /// <param name="resourceId">Optional, the AD resource id, used as the audience of the providded tokens.</param>
        /// <returns>A token provider using the credentials the user entered through the dialog</returns>
        ITokenProvider Login(AzureAccount account, AzureEnvironment environment, string tenant, ShowDialog promptBehavior,
            AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId);
        
        /// <summary>
        /// Log in using a login prompt. Returns ITokenProvider if authentication succeeds or throws an exception if 
        /// authentication fails.
        /// </summary>
        /// <param name="account">The azure account object</param>
        /// <param name="environment">The azure environment object</param>
        /// <param name="tenant">The AD tenant in most cases should be 'common'</param>
        /// <param name="promptBehavior">The prompt behavior</param>
        /// <param name="cache">The tpoken cache to target during authentication.</param>
        /// <param name="resourceId">Optional, the AD resource id, used as the audience of the providded tokens.</param>
        /// <returns>A token provider using the credentials the user entered through the dialog</returns>
        ITokenProvider Login(AzureAccount account, AzureEnvironment environment, string tenant, ShowDialog promptBehavior,
            TokenCache cache, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId);

        /// <summary>
        /// Log in using the provided credentials, without a log in prompt.
        /// </summary>
        /// <param name="account">The azure account object</param>
        /// <param name="environment">The azure environment object</param>
        /// <param name="tenant">The AD tenant in most cases should be 'common'</param>
        /// <param name="password">The psssword or secret associated with the given account.</param>
        /// <param name="resourceId">Optional, the AD resource id, used as the audience of the providded tokens.</param>
        /// <returns>A token provider using the given credentials.</returns>
        ITokenProvider Login(AzureAccount account, AzureEnvironment environment, string tenant, 
            SecureString password, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId);
        
        /// <summary>
        /// Log in using the provided credentials, without a log in prompt.
        /// </summary>
        /// <param name="account">The azure account object</param>
        /// <param name="environment">The azure environment object</param>
        /// <param name="tenant">The AD tenant in most cases should be 'common'</param>
        /// <param name="password">The psssword or secret associated with the given account.</param>
        /// <param name="cache">The token cache to target during authentication.</param>
        /// <param name="resourceId">Optional, the AD resource id, used as the audience of the providded tokens.</param>
        /// <returns>A token provider using the given credentials.</returns>
        ITokenProvider Login(AzureAccount account, AzureEnvironment environment, string tenant, 
            SecureString password, TokenCache cache, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId);
        
        /// <summary>
        /// Get a token provider after an initial login.
        /// </summary>
        /// <param name="account">The azure account object</param>
        /// <param name="environment">The azure environment object</param>
        /// <param name="tenant">The AD tenant in most cases should be 'common'</param>
        /// <param name="resourceId">Optional, the AD resource id, used as the audience of the providded tokens.</param>
        /// <returns>A token provider using tokens from the cache.</returns>
        ITokenProvider Authenticate(AzureAccount account, AzureEnvironment environment, string tenant,
            AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId);
        
        /// <summary>
        /// Get a token provider after an initial login.
        /// </summary>
        /// <param name="account">The azure account object</param>
        /// <param name="environment">The azure environment object</param>
        /// <param name="tenant">The AD tenant in most cases should be 'common'</param>
        /// <param name="cache">The token cache to target during authentication.</param>
        /// <param name="resourceId">Optional, the AD resource id, used as the audience of the providded tokens.</param>
        /// <returns>A token provider using tokens from the cache.</returns>
        ITokenProvider Authenticate(AzureAccount account, AzureEnvironment environment, string tenant,
            TokenCache cache, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId);
        
        /// <summary>
        /// Get credentials for the current azure context for use with legacy management clients.
        /// </summary>
        /// <param name="context">The current management contest for azure, including the username, tenant, and subscription.</param>
        /// <returns>SubscriptionCloudCredentials with valid authentication tokens for the given context.</returns>
        SubscriptionCloudCredentials GetSubscriptionCloudCredentials(AzureContext context, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId);

        /// <summary>
        /// Get credentials for the current azure context for use with legacy management clients.
        /// </summary>
        /// <param name="context">The current management contest for azure, including the username, tenant, and subscription.</param>
        /// <param name="cache">The token cache to target during authentcation.  The token cache shoudl contains cached tokens from a previous login.</param>
        /// <returns>SubscriptionCloudCredentials with valid authentication tokens for the given context.</returns>
        SubscriptionCloudCredentials GetSubscriptionCloudCredentials(AzureContext context, TokenCache cache, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId);
        
        /// <summary>
        /// Get credentials for the current azure context for use with AutoRest-generated management clients.
        /// </summary>
        /// <param name="context">The current management contest for azure, including the username, tenant, and subscription.</param>
        /// <returns>ServiceClientCredentials with valid authentication tokens for the given context.</returns>
        ServiceClientCredentials GetServiceClientCredentials(AzureContext context, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId);
        
        /// <summary>
        /// Get credentials for the current azure context for use with AutoRest-generated management clients.
        /// </summary>
        /// <param name="context">The current management contest for azure, including the username, tenant, and subscription.</param>
        /// <param name="cache">The token cache to target during authentcation.  The token cache shoudl contains cached tokens from a previous login.</param>
        /// <returns>ServiceClientCredentials with valid authentication tokens for the given context.</returns>
        ServiceClientCredentials GetServiceClientCredentials(AzureContext context, TokenCache cache, AzureEnvironment.Endpoint resourceId = AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId);
    }
}
