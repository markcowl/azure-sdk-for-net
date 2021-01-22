// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Azure.Core.TestFramework;

namespace Azure.ResourceManager.Authorization.Tests
{
    public class AuthorizationManagementTestEnvironment : TestEnvironment
    {
        public AuthorizationManagementTestEnvironment() : base("authorizationmgmt")
        {
        }
    }
}