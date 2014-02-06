// 
// Copyright (c) Microsoft and contributors.  All rights reserved.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//   http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 
// See the License for the specific language governing permissions and
// limitations under the License.
// 

// Warning: This code was generated by a tool.
// 
// Changes to this file may cause incorrect behavior and will be lost if the
// code is regenerated.

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.WindowsAzure.Management.Store;
using Microsoft.WindowsAzure.Management.Store.Models;

namespace Microsoft.WindowsAzure.Management.Store
{
    /// <summary>
    /// The Windows Azure Store API is a REST API for managing Windows Azure
    /// Store add-ins.
    /// </summary>
    public static partial class CloudServiceOperationsExtensions
    {
        /// <summary>
        /// The Create Cloud Service operation creates a Windows Azure cloud
        /// service in a Windows Azure subscription.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Store.ICloudServiceOperations.
        /// </param>
        /// <param name='parameters'>
        /// Parameters used to specify how the Create procedure will function.
        /// </param>
        /// <returns>
        /// The response body contains the status of the specified asynchronous
        /// operation, indicating whether it has succeeded, is inprogress, or
        /// has failed. Note that this status is distinct from the HTTP status
        /// code returned for the Get Operation Status operation itself.  If
        /// the asynchronous operation succeeded, the response body includes
        /// the HTTP status code for the successful request.  If the
        /// asynchronous operation failed, the response body includes the HTTP
        /// status code for the failed request, and also includes error
        /// information regarding the failure.
        /// </returns>
        public static AddOnOperationStatusResponse BeginCreating(this ICloudServiceOperations operations, CloudServiceCreateParameters parameters)
        {
            try
            {
                return operations.BeginCreatingAsync(parameters).Result;
            }
            catch (AggregateException ex)
            {
                if (ex.InnerExceptions.Count > 1)
                {
                    throw;
                }
                else
                {
                    throw ex.InnerException;
                }
            }
        }
        
        /// <summary>
        /// The Create Cloud Service operation creates a Windows Azure cloud
        /// service in a Windows Azure subscription.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Store.ICloudServiceOperations.
        /// </param>
        /// <param name='parameters'>
        /// Parameters used to specify how the Create procedure will function.
        /// </param>
        /// <returns>
        /// The response body contains the status of the specified asynchronous
        /// operation, indicating whether it has succeeded, is inprogress, or
        /// has failed. Note that this status is distinct from the HTTP status
        /// code returned for the Get Operation Status operation itself.  If
        /// the asynchronous operation succeeded, the response body includes
        /// the HTTP status code for the successful request.  If the
        /// asynchronous operation failed, the response body includes the HTTP
        /// status code for the failed request, and also includes error
        /// information regarding the failure.
        /// </returns>
        public static Task<AddOnOperationStatusResponse> BeginCreatingAsync(this ICloudServiceOperations operations, CloudServiceCreateParameters parameters)
        {
            return operations.BeginCreatingAsync(parameters, CancellationToken.None);
        }
        
        /// <summary>
        /// The Create Cloud Service operation creates a Windows Azure cloud
        /// service in a Windows Azure subscription.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Store.ICloudServiceOperations.
        /// </param>
        /// <param name='parameters'>
        /// Parameters used to specify how the Create procedure will function.
        /// </param>
        /// <returns>
        /// The response body contains the status of the specified asynchronous
        /// operation, indicating whether it has succeeded, is inprogress, or
        /// has failed. Note that this status is distinct from the HTTP status
        /// code returned for the Get Operation Status operation itself.  If
        /// the asynchronous operation succeeded, the response body includes
        /// the HTTP status code for the successful request.  If the
        /// asynchronous operation failed, the response body includes the HTTP
        /// status code for the failed request, and also includes error
        /// information regarding the failure.
        /// </returns>
        public static AddOnOperationStatusResponse Create(this ICloudServiceOperations operations, CloudServiceCreateParameters parameters)
        {
            try
            {
                return operations.CreateAsync(parameters).Result;
            }
            catch (AggregateException ex)
            {
                if (ex.InnerExceptions.Count > 1)
                {
                    throw;
                }
                else
                {
                    throw ex.InnerException;
                }
            }
        }
        
        /// <summary>
        /// The Create Cloud Service operation creates a Windows Azure cloud
        /// service in a Windows Azure subscription.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Store.ICloudServiceOperations.
        /// </param>
        /// <param name='parameters'>
        /// Parameters used to specify how the Create procedure will function.
        /// </param>
        /// <returns>
        /// The response body contains the status of the specified asynchronous
        /// operation, indicating whether it has succeeded, is inprogress, or
        /// has failed. Note that this status is distinct from the HTTP status
        /// code returned for the Get Operation Status operation itself.  If
        /// the asynchronous operation succeeded, the response body includes
        /// the HTTP status code for the successful request.  If the
        /// asynchronous operation failed, the response body includes the HTTP
        /// status code for the failed request, and also includes error
        /// information regarding the failure.
        /// </returns>
        public static Task<AddOnOperationStatusResponse> CreateAsync(this ICloudServiceOperations operations, CloudServiceCreateParameters parameters)
        {
            return operations.CreateAsync(parameters, CancellationToken.None);
        }
        
        /// <summary>
        /// The List Cloud Services operation enumerates Windows Azure Store
        /// entries that are provisioned for a subscription.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Store.ICloudServiceOperations.
        /// </param>
        /// <returns>
        /// The response structure for the Cloud Service List operation.
        /// </returns>
        public static CloudServiceListResponse List(this ICloudServiceOperations operations)
        {
            try
            {
                return operations.ListAsync().Result;
            }
            catch (AggregateException ex)
            {
                if (ex.InnerExceptions.Count > 1)
                {
                    throw;
                }
                else
                {
                    throw ex.InnerException;
                }
            }
        }
        
        /// <summary>
        /// The List Cloud Services operation enumerates Windows Azure Store
        /// entries that are provisioned for a subscription.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Store.ICloudServiceOperations.
        /// </param>
        /// <returns>
        /// The response structure for the Cloud Service List operation.
        /// </returns>
        public static Task<CloudServiceListResponse> ListAsync(this ICloudServiceOperations operations)
        {
            return operations.ListAsync(CancellationToken.None);
        }
    }
}
