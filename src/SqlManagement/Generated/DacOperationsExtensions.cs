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
using Microsoft.WindowsAzure.Management.Sql;
using Microsoft.WindowsAzure.Management.Sql.Models;

namespace Microsoft.WindowsAzure.Management.Sql
{
    /// <summary>
    /// The SQL Database Management API is a REST API for managing SQL Database
    /// servers and the firewall rules associated with SQL Database servers.
    /// (see
    /// http://msdn.microsoft.com/en-us/library/windowsazure/gg715283.aspx for
    /// more information)
    /// </summary>
    public static partial class DacOperationsExtensions
    {
        /// <summary>
        /// Export DAC into Windows Azure blob storage.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Sql.IDacOperations.
        /// </param>
        /// <param name='serverName'>
        /// The name of the server being exported from.
        /// </param>
        /// <param name='parameters'>
        /// Export parameters.
        /// </param>
        /// <returns>
        /// Response for an DAC Import/Export request.
        /// </returns>
        public static DacImportExportResponse Export(this IDacOperations operations, string serverName, DacExportParameters parameters)
        {
            try
            {
                return operations.ExportAsync(serverName, parameters).Result;
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
        /// Export DAC into Windows Azure blob storage.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Sql.IDacOperations.
        /// </param>
        /// <param name='serverName'>
        /// The name of the server being exported from.
        /// </param>
        /// <param name='parameters'>
        /// Export parameters.
        /// </param>
        /// <returns>
        /// Response for an DAC Import/Export request.
        /// </returns>
        public static Task<DacImportExportResponse> ExportAsync(this IDacOperations operations, string serverName, DacExportParameters parameters)
        {
            return operations.ExportAsync(serverName, parameters, CancellationToken.None);
        }
        
        /// <summary>
        /// Gets the status of the DAC.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Sql.IDacOperations.
        /// </param>
        /// <param name='serverName'>
        /// The name of the server.
        /// </param>
        /// <param name='fullyQualifiedServerName'>
        /// The fully qualified name of the server.
        /// </param>
        /// <param name='username'>
        /// The server's username.
        /// </param>
        /// <param name='password'>
        /// The server's password.
        /// </param>
        /// <param name='requestId'>
        /// The request ID of the operation being queried.
        /// </param>
        /// <returns>
        /// The response structure for the DAC GetStatus operation.
        /// </returns>
        public static DacGetStatusResponse GetStatus(this IDacOperations operations, string serverName, string fullyQualifiedServerName, string username, string password, string requestId)
        {
            try
            {
                return operations.GetStatusAsync(serverName, fullyQualifiedServerName, username, password, requestId).Result;
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
        /// Gets the status of the DAC.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Sql.IDacOperations.
        /// </param>
        /// <param name='serverName'>
        /// The name of the server.
        /// </param>
        /// <param name='fullyQualifiedServerName'>
        /// The fully qualified name of the server.
        /// </param>
        /// <param name='username'>
        /// The server's username.
        /// </param>
        /// <param name='password'>
        /// The server's password.
        /// </param>
        /// <param name='requestId'>
        /// The request ID of the operation being queried.
        /// </param>
        /// <returns>
        /// The response structure for the DAC GetStatus operation.
        /// </returns>
        public static Task<DacGetStatusResponse> GetStatusAsync(this IDacOperations operations, string serverName, string fullyQualifiedServerName, string username, string password, string requestId)
        {
            return operations.GetStatusAsync(serverName, fullyQualifiedServerName, username, password, requestId, CancellationToken.None);
        }
        
        /// <summary>
        /// Import DAC from Windows Azure blob storage.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Sql.IDacOperations.
        /// </param>
        /// <param name='serverName'>
        /// The name of the server being imported to.
        /// </param>
        /// <param name='parameters'>
        /// Import parameters.
        /// </param>
        /// <returns>
        /// Response for an DAC Import/Export request.
        /// </returns>
        public static DacImportExportResponse Import(this IDacOperations operations, string serverName, DacImportParameters parameters)
        {
            try
            {
                return operations.ImportAsync(serverName, parameters).Result;
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
        /// Import DAC from Windows Azure blob storage.
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Sql.IDacOperations.
        /// </param>
        /// <param name='serverName'>
        /// The name of the server being imported to.
        /// </param>
        /// <param name='parameters'>
        /// Import parameters.
        /// </param>
        /// <returns>
        /// Response for an DAC Import/Export request.
        /// </returns>
        public static Task<DacImportExportResponse> ImportAsync(this IDacOperations operations, string serverName, DacImportParameters parameters)
        {
            return operations.ImportAsync(serverName, parameters, CancellationToken.None);
        }
    }
}
