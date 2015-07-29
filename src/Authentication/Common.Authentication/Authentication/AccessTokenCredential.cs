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

using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Rest;

namespace Microsoft.Azure.Common.Authentication
{
    public class AccessTokenCredential : SubscriptionCloudCredentials
    {
        private readonly Guid subscriptionId;
        private readonly ITokenProvider tokenProvider;

        public AccessTokenCredential(Guid subscriptionId, ITokenProvider provider)
        {
            this.subscriptionId = subscriptionId;
            this.tokenProvider = provider;
        }
        
        public AccessTokenCredential(ITokenProvider provider)
        {
            this.subscriptionId = Guid.NewGuid();
            this.tokenProvider = provider;
        }
        
        public override Task ProcessHttpRequestAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var authenticationHeader = tokenProvider.GetAuthenticationHeaderAsync(cancellationToken).Result;
            request.Headers.Authorization = authenticationHeader;
            return base.ProcessHttpRequestAsync(request, cancellationToken);
        }

        public override string SubscriptionId
        {
            get { return subscriptionId.ToString(); }
        }
    }
}