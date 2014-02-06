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
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.WindowsAzure;
using Microsoft.WindowsAzure.WebSitesExtensions;
using Microsoft.WindowsAzure.WebSitesExtensions.Models;

namespace Microsoft.WindowsAzure.WebSitesExtensions
{
    /// <summary>
    /// TBD.
    /// </summary>
    public static partial class RepositoryOperationsExtensions
    {
        /// <summary>
        /// Deletes the repository.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.WebSitesExtensions.IRepositoryOperations.
        /// </param>
        /// <returns>
        /// A standard service response including an HTTP status code and
        /// request ID.
        /// </returns>
        public static OperationResponse Delete(this IRepositoryOperations operations)
        {
            try
            {
                return operations.DeleteAsync().Result;
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
        /// Deletes the repository.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.WebSitesExtensions.IRepositoryOperations.
        /// </param>
        /// <returns>
        /// A standard service response including an HTTP status code and
        /// request ID.
        /// </returns>
        public static Task<OperationResponse> DeleteAsync(this IRepositoryOperations operations)
        {
            return operations.DeleteAsync(CancellationToken.None);
        }
        
        /// <summary>
        /// Get diagnostics settings.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.WebSitesExtensions.IRepositoryOperations.
        /// </param>
        /// <returns>
        /// The get diagnostic settings operation response.
        /// </returns>
        public static DiagnosticGetResponse GetSettings(this IRepositoryOperations operations)
        {
            try
            {
                return operations.GetSettingsAsync().Result;
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
        /// Get diagnostics settings.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.WebSitesExtensions.IRepositoryOperations.
        /// </param>
        /// <returns>
        /// The get diagnostic settings operation response.
        /// </returns>
        public static Task<DiagnosticGetResponse> GetSettingsAsync(this IRepositoryOperations operations)
        {
            return operations.GetSettingsAsync(CancellationToken.None);
        }
        
        /// <summary>
        /// Update diagnostics settings.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.WebSitesExtensions.IRepositoryOperations.
        /// </param>
        /// <param name='settings'>
        /// The diagnostics setting information new values.
        /// </param>
        /// <returns>
        /// A standard service response including an HTTP status code and
        /// request ID.
        /// </returns>
        public static OperationResponse Update(this IRepositoryOperations operations, IDictionary<string, string> settings)
        {
            try
            {
                return operations.UpdateAsync(settings).Result;
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
        /// Update diagnostics settings.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.WebSitesExtensions.IRepositoryOperations.
        /// </param>
        /// <param name='settings'>
        /// The diagnostics setting information new values.
        /// </param>
        /// <returns>
        /// A standard service response including an HTTP status code and
        /// request ID.
        /// </returns>
        public static Task<OperationResponse> UpdateAsync(this IRepositoryOperations operations, IDictionary<string, string> settings)
        {
            return operations.UpdateAsync(settings, CancellationToken.None);
        }
    }
}
