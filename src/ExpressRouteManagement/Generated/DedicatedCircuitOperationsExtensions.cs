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
using Microsoft.WindowsAzure.Management.ExpressRoute;
using Microsoft.WindowsAzure.Management.ExpressRoute.Models;

namespace Microsoft.WindowsAzure.Management.ExpressRoute
{
    /// <summary>
    /// The Express Route API provides programmatic access to the functionality
    /// needed by the customer to set up Dedicated Circuits and Dedicated
    /// Circuit Links. The Express Route Customer API is a REST API. All API
    /// operations are performed over SSL and mutually authenticated using
    /// X.509 v3 certificates.  (see
    /// http://msdn.microsoft.com/en-us/library/windowsazure/ee460799.aspx for
    /// more information)
    /// </summary>
    public static partial class DedicatedCircuitOperationsExtensions
    {
        /// <summary>
        /// The New Dedicated Circuit operation creates a new dedicated circuit.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.ExpressRoute.IDedicatedCircuitOperations.
        /// </param>
        /// <param name='parameters'>
        /// Parameters supplied to the New Dedicated Circuit operation.
        /// </param>
        /// <returns>
        /// A standard express route gateway response including an HTTP status
        /// code and request ID.
        /// </returns>
        public static ExpressRouteOperationResponse BeginNew(this IDedicatedCircuitOperations operations, DedicatedCircuitNewParameters parameters)
        {
            try
            {
                return operations.BeginNewAsync(parameters).Result;
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
        /// The New Dedicated Circuit operation creates a new dedicated circuit.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.ExpressRoute.IDedicatedCircuitOperations.
        /// </param>
        /// <param name='parameters'>
        /// Parameters supplied to the New Dedicated Circuit operation.
        /// </param>
        /// <returns>
        /// A standard express route gateway response including an HTTP status
        /// code and request ID.
        /// </returns>
        public static Task<ExpressRouteOperationResponse> BeginNewAsync(this IDedicatedCircuitOperations operations, DedicatedCircuitNewParameters parameters)
        {
            return operations.BeginNewAsync(parameters, CancellationToken.None);
        }
        
        /// <summary>
        /// The Remove Dedicated Circuit operation deletes an existing
        /// dedicated circuit.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.ExpressRoute.IDedicatedCircuitOperations.
        /// </param>
        /// <param name='serviceKey'>
        /// Service key representing the dedicated circuit to be deleted.
        /// </param>
        /// <returns>
        /// A standard express route gateway response including an HTTP status
        /// code and request ID.
        /// </returns>
        public static ExpressRouteOperationResponse BeginRemove(this IDedicatedCircuitOperations operations, string serviceKey)
        {
            try
            {
                return operations.BeginRemoveAsync(serviceKey).Result;
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
        /// The Remove Dedicated Circuit operation deletes an existing
        /// dedicated circuit.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.ExpressRoute.IDedicatedCircuitOperations.
        /// </param>
        /// <param name='serviceKey'>
        /// Service key representing the dedicated circuit to be deleted.
        /// </param>
        /// <returns>
        /// A standard express route gateway response including an HTTP status
        /// code and request ID.
        /// </returns>
        public static Task<ExpressRouteOperationResponse> BeginRemoveAsync(this IDedicatedCircuitOperations operations, string serviceKey)
        {
            return operations.BeginRemoveAsync(serviceKey, CancellationToken.None);
        }
        
        /// <summary>
        /// The Get Dedicated Circuit operation retrieves the specified
        /// dedicated circuit.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.ExpressRoute.IDedicatedCircuitOperations.
        /// </param>
        /// <param name='serviceKey'>
        /// The service key representing the circuit.
        /// </param>
        /// <returns>
        /// The Get Dedicated Circuit operation response.
        /// </returns>
        public static DedicatedCircuitGetResponse Get(this IDedicatedCircuitOperations operations, string serviceKey)
        {
            try
            {
                return operations.GetAsync(serviceKey).Result;
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
        /// The Get Dedicated Circuit operation retrieves the specified
        /// dedicated circuit.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.ExpressRoute.IDedicatedCircuitOperations.
        /// </param>
        /// <param name='serviceKey'>
        /// The service key representing the circuit.
        /// </param>
        /// <returns>
        /// The Get Dedicated Circuit operation response.
        /// </returns>
        public static Task<DedicatedCircuitGetResponse> GetAsync(this IDedicatedCircuitOperations operations, string serviceKey)
        {
            return operations.GetAsync(serviceKey, CancellationToken.None);
        }
        
        /// <summary>
        /// The List Dedicated Circuit operation retrieves a list of dedicated
        /// circuits owned by the customer.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.ExpressRoute.IDedicatedCircuitOperations.
        /// </param>
        /// <returns>
        /// The List Dedicated Circuit operation response.
        /// </returns>
        public static DedicatedCircuitListResponse List(this IDedicatedCircuitOperations operations)
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
        /// The List Dedicated Circuit operation retrieves a list of dedicated
        /// circuits owned by the customer.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.ExpressRoute.IDedicatedCircuitOperations.
        /// </param>
        /// <returns>
        /// The List Dedicated Circuit operation response.
        /// </returns>
        public static Task<DedicatedCircuitListResponse> ListAsync(this IDedicatedCircuitOperations operations)
        {
            return operations.ListAsync(CancellationToken.None);
        }
        
        /// <summary>
        /// The New Dedicated Circuit operation creates a new dedicated circuit.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.ExpressRoute.IDedicatedCircuitOperations.
        /// </param>
        /// <param name='parameters'>
        /// Parameters supplied to the Create Virtual Network Gateway operation.
        /// </param>
        /// <returns>
        /// The Get Dedicated Circuit operation response.
        /// </returns>
        public static DedicatedCircuitGetResponse New(this IDedicatedCircuitOperations operations, DedicatedCircuitNewParameters parameters)
        {
            try
            {
                return operations.NewAsync(parameters).Result;
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
        /// The New Dedicated Circuit operation creates a new dedicated circuit.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.ExpressRoute.IDedicatedCircuitOperations.
        /// </param>
        /// <param name='parameters'>
        /// Parameters supplied to the Create Virtual Network Gateway operation.
        /// </param>
        /// <returns>
        /// The Get Dedicated Circuit operation response.
        /// </returns>
        public static Task<DedicatedCircuitGetResponse> NewAsync(this IDedicatedCircuitOperations operations, DedicatedCircuitNewParameters parameters)
        {
            return operations.NewAsync(parameters, CancellationToken.None);
        }
        
        /// <summary>
        /// The Remove Dedicated Circuit operation deletes an existing
        /// dedicated circuit.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.ExpressRoute.IDedicatedCircuitOperations.
        /// </param>
        /// <param name='serviceKey'>
        /// Service Key associated with the dedicated circuit to be deleted.
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
        public static ExpressRouteOperationStatusResponse Remove(this IDedicatedCircuitOperations operations, string serviceKey)
        {
            try
            {
                return operations.RemoveAsync(serviceKey).Result;
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
        /// The Remove Dedicated Circuit operation deletes an existing
        /// dedicated circuit.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.ExpressRoute.IDedicatedCircuitOperations.
        /// </param>
        /// <param name='serviceKey'>
        /// Service Key associated with the dedicated circuit to be deleted.
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
        public static Task<ExpressRouteOperationStatusResponse> RemoveAsync(this IDedicatedCircuitOperations operations, string serviceKey)
        {
            return operations.RemoveAsync(serviceKey, CancellationToken.None);
        }
    }
}
