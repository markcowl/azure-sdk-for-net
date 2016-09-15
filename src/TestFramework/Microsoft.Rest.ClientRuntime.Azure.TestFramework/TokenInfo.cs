// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Microsoft.Rest.ClientRuntime.Azure.TestFramework
{
    public class TokenInfo
    {
        bool _rawToken = false;
        AuthenticationResult _result;

        public TokenInfo(string accessToken)
        {
            AccessToken = accessToken;
            AccessTokenType = "Bearer";
        }

        public TokenInfo(AuthenticationResult result, AuthenticationContext context)
        {
            Context = context;
            Result = result;
            AccessToken = result.AccessToken;
            AccessTokenType = result.AccessTokenType;
        }

        public TokenInfo(AuthenticationResult result, AuthenticationContext context, string clientId, string secret)
        {
            Context = context;
            Result = result;
            AccessToken = result.AccessToken;
            AccessTokenType = result.AccessTokenType;
            ClientId = clientId;
            ClientSecret = secret;
        }

        public string AccessToken { get; private set; }

        public string AccessTokenType { get; private set; }

        public AuthenticationResult Result { get; private set; }

        public AuthenticationContext Context { get; private set; }

        public string ClientId { get; private set; }

        public string ClientSecret { get; private set; }
    }
}
