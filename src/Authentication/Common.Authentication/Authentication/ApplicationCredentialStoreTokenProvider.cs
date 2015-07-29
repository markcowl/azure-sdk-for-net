using System;
using System.Globalization;
using System.Security;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Rest.Azure.Authentication;

namespace Microsoft.Azure.Common.Authentication
{
    /// <summary>
    /// An active directory application token provider, with credentials stored in the credential store
    /// </summary>
    public class ApplicationCredentialStoreTokenProvider : ActiveDirectoryApplicationTokenProvider
    {
        /// <summary>
        /// Creates an active directory token provider and stores it in the credential store.
        /// </summary>
        /// <param name="clientId">The client id for this application.</param>
        /// <param name="domain">The active directory domainfor the provided tokens.</param>
        /// <param name="secret">The client secret for the application.</param>
        /// <param name="environment">The active directory environment to target.</param>
        public ApplicationCredentialStoreTokenProvider(string clientId, string domain, string secret, ActiveDirectoryEnvironment environment, TokenCache cache) 
            : base(clientId, domain, secret, environment, cache)
        {
            StoreAppKey(clientId, domain, secret);
        }


        /// <summary>
        /// Retrieve an application token provider from the credential store.
        /// </summary>
        /// <param name="clientId"></param>
        /// <param name="domain"></param>
        /// <param name="environment"></param>
        /// <returns></returns>
        public static ActiveDirectoryApplicationTokenProvider GetProviderFromCredStore(string clientId, string domain, ActiveDirectoryEnvironment environment)
        {
            var secureSecret = LoadAppKey(clientId, domain);
            if (secureSecret == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, 
                    "Could not find credentials for application {0} in domain {1}", clientId, domain));
            }

            return new ActiveDirectoryApplicationTokenProvider(clientId, domain, 
                TokenProviderUtilities.ConvertToString(secureSecret), environment);
        }

        public static ActiveDirectoryApplicationTokenProvider GetProviderFromCredStore(string clientId, string domain, ActiveDirectoryEnvironment environment, TokenCache cache)
        {
            var secureSecret = LoadAppKey(clientId, domain);
            if (secureSecret == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, 
                    "Could not find credentials for application {0} in domain {1}", clientId, domain));
            }

            return new ActiveDirectoryApplicationTokenProvider(clientId, domain, 
                TokenProviderUtilities.ConvertToString(secureSecret), environment, cache);
        }

       private static SecureString LoadAppKey(string clientId, string domain)
        {
            return ServicePrincipalKeyStore.GetKey(clientId, domain);
        }

        private static void StoreAppKey(string clientId, string domain, string secret)
        {
            SecureString secureSecret = new SecureString();
            foreach(var secretChar in secret)
            {
                secureSecret.AppendChar(secretChar);
            }

           ServicePrincipalKeyStore.SaveKey(clientId, domain, secureSecret);
        }

    }
}
