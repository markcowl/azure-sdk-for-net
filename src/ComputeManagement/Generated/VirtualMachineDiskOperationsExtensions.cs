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
using Microsoft.WindowsAzure;
using Microsoft.WindowsAzure.Management.Compute;
using Microsoft.WindowsAzure.Management.Compute.Models;

namespace Microsoft.WindowsAzure.Management.Compute
{
    /// <summary>
    /// The Service Management API provides programmatic access to much of the
    /// functionality available through the Management Portal. The Service
    /// Management API is a REST API. All API operations are performed over
    /// SSL and mutually authenticated using X.509 v3 certificates.  (see
    /// http://msdn.microsoft.com/en-us/library/windowsazure/ee460799.aspx for
    /// more information)
    /// </summary>
    public static partial class VirtualMachineDiskOperationsExtensions
    {
        /// <summary>
        /// The Delete Data Disk operation removes the specified data disk from
        /// a virtual machine.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157179.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='serviceName'>
        /// The name of your service.
        /// </param>
        /// <param name='deploymentName'>
        /// The name of the deployment.
        /// </param>
        /// <param name='roleName'>
        /// The name of the role to delete the data disk from.
        /// </param>
        /// <param name='logicalUnitNumber'>
        /// The logical unit number of the disk.
        /// </param>
        /// <param name='deleteFromStorage'>
        /// Optional. Specifies that the source blob for the disk should also
        /// be deleted from storage.
        /// </param>
        /// <returns>
        /// A standard service response including an HTTP status code and
        /// request ID.
        /// </returns>
        public static OperationResponse BeginDeletingDataDisk(this IVirtualMachineDiskOperations operations, string serviceName, string deploymentName, string roleName, int logicalUnitNumber, bool deleteFromStorage)
        {
            try
            {
                return operations.BeginDeletingDataDiskAsync(serviceName, deploymentName, roleName, logicalUnitNumber, deleteFromStorage).Result;
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
        /// The Delete Data Disk operation removes the specified data disk from
        /// a virtual machine.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157179.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='serviceName'>
        /// The name of your service.
        /// </param>
        /// <param name='deploymentName'>
        /// The name of the deployment.
        /// </param>
        /// <param name='roleName'>
        /// The name of the role to delete the data disk from.
        /// </param>
        /// <param name='logicalUnitNumber'>
        /// The logical unit number of the disk.
        /// </param>
        /// <param name='deleteFromStorage'>
        /// Optional. Specifies that the source blob for the disk should also
        /// be deleted from storage.
        /// </param>
        /// <returns>
        /// A standard service response including an HTTP status code and
        /// request ID.
        /// </returns>
        public static Task<OperationResponse> BeginDeletingDataDiskAsync(this IVirtualMachineDiskOperations operations, string serviceName, string deploymentName, string roleName, int logicalUnitNumber, bool deleteFromStorage)
        {
            return operations.BeginDeletingDataDiskAsync(serviceName, deploymentName, roleName, logicalUnitNumber, deleteFromStorage, CancellationToken.None);
        }
        
        /// <summary>
        /// The Add Data Disk operation adds a data disk to a virtual machine.
        /// There are three ways to create the data disk using the Add Data
        /// Disk operation.  Option 1 – Attach an empty data disk to the role
        /// by specifying the disk label and location of the disk image.  Do
        /// not include the DiskName and SourceMediaLink elements in the
        /// request body.  Include the MediaLink element and reference a blob
        /// that is in the same geographical region as the role.  You can also
        /// omit the MediaLink element. In this usage, Windows Azure will
        /// create the data disk in the storage account configured as default
        /// for the role.   Option 2 – Attach an existing data disk that is in
        /// the image repository.  Do not include the DiskName and
        /// SourceMediaLink elements in the request body.  Specify the data
        /// disk to use by including the DiskName element.  Note: If included
        /// the in the response body, the MediaLink and LogicalDiskSizeInGB
        /// elements are ignored.  Option 3 - Specify the location of a blob
        /// in your storage account that contain a disk image to use.  Include
        /// the SourceMediaLink element. Note: If the MediaLink element
        /// isincluded, it is ignored.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157199.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='serviceName'>
        /// The name of your service.
        /// </param>
        /// <param name='deploymentName'>
        /// The name of the deployment.
        /// </param>
        /// <param name='roleName'>
        /// The name of the role to add the data disk to.
        /// </param>
        /// <param name='parameters'>
        /// Parameters supplied to the Create Virtual Machine Data Disk
        /// operation.
        /// </param>
        /// <returns>
        /// A standard service response including an HTTP status code and
        /// request ID.
        /// </returns>
        public static OperationResponse CreateDataDisk(this IVirtualMachineDiskOperations operations, string serviceName, string deploymentName, string roleName, VirtualMachineDiskCreateDataDiskParameters parameters)
        {
            try
            {
                return operations.CreateDataDiskAsync(serviceName, deploymentName, roleName, parameters).Result;
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
        /// The Add Data Disk operation adds a data disk to a virtual machine.
        /// There are three ways to create the data disk using the Add Data
        /// Disk operation.  Option 1 – Attach an empty data disk to the role
        /// by specifying the disk label and location of the disk image.  Do
        /// not include the DiskName and SourceMediaLink elements in the
        /// request body.  Include the MediaLink element and reference a blob
        /// that is in the same geographical region as the role.  You can also
        /// omit the MediaLink element. In this usage, Windows Azure will
        /// create the data disk in the storage account configured as default
        /// for the role.   Option 2 – Attach an existing data disk that is in
        /// the image repository.  Do not include the DiskName and
        /// SourceMediaLink elements in the request body.  Specify the data
        /// disk to use by including the DiskName element.  Note: If included
        /// the in the response body, the MediaLink and LogicalDiskSizeInGB
        /// elements are ignored.  Option 3 - Specify the location of a blob
        /// in your storage account that contain a disk image to use.  Include
        /// the SourceMediaLink element. Note: If the MediaLink element
        /// isincluded, it is ignored.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157199.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='serviceName'>
        /// The name of your service.
        /// </param>
        /// <param name='deploymentName'>
        /// The name of the deployment.
        /// </param>
        /// <param name='roleName'>
        /// The name of the role to add the data disk to.
        /// </param>
        /// <param name='parameters'>
        /// Parameters supplied to the Create Virtual Machine Data Disk
        /// operation.
        /// </param>
        /// <returns>
        /// A standard service response including an HTTP status code and
        /// request ID.
        /// </returns>
        public static Task<OperationResponse> CreateDataDiskAsync(this IVirtualMachineDiskOperations operations, string serviceName, string deploymentName, string roleName, VirtualMachineDiskCreateDataDiskParameters parameters)
        {
            return operations.CreateDataDiskAsync(serviceName, deploymentName, roleName, parameters, CancellationToken.None);
        }
        
        /// <summary>
        /// The Add Disk operation adds a disk to the user image repository.
        /// The disk can be an operating system disk or a data disk.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157178.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='parameters'>
        /// Parameters supplied to the Create Virtual Machine Disk operation.
        /// </param>
        /// <returns>
        /// A virtual machine disk associated with your subscription.
        /// </returns>
        public static VirtualMachineDiskCreateDiskResponse CreateDisk(this IVirtualMachineDiskOperations operations, VirtualMachineDiskCreateDiskParameters parameters)
        {
            try
            {
                return operations.CreateDiskAsync(parameters).Result;
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
        /// The Add Disk operation adds a disk to the user image repository.
        /// The disk can be an operating system disk or a data disk.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157178.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='parameters'>
        /// Parameters supplied to the Create Virtual Machine Disk operation.
        /// </param>
        /// <returns>
        /// A virtual machine disk associated with your subscription.
        /// </returns>
        public static Task<VirtualMachineDiskCreateDiskResponse> CreateDiskAsync(this IVirtualMachineDiskOperations operations, VirtualMachineDiskCreateDiskParameters parameters)
        {
            return operations.CreateDiskAsync(parameters, CancellationToken.None);
        }
        
        /// <summary>
        /// The Delete Data Disk operation removes the specified data disk from
        /// a virtual machine.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157179.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='serviceName'>
        /// The name of your service.
        /// </param>
        /// <param name='deploymentName'>
        /// The name of the deployment.
        /// </param>
        /// <param name='roleName'>
        /// The name of the role to delete the data disk from.
        /// </param>
        /// <param name='logicalUnitNumber'>
        /// The logical unit number of the disk.
        /// </param>
        /// <param name='deleteFromStorage'>
        /// Optional. Specifies that the source blob for the disk should also
        /// be deleted from storage.
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
        public static ComputeOperationStatusResponse DeleteDataDisk(this IVirtualMachineDiskOperations operations, string serviceName, string deploymentName, string roleName, int logicalUnitNumber, bool deleteFromStorage)
        {
            try
            {
                return operations.DeleteDataDiskAsync(serviceName, deploymentName, roleName, logicalUnitNumber, deleteFromStorage).Result;
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
        /// The Delete Data Disk operation removes the specified data disk from
        /// a virtual machine.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157179.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='serviceName'>
        /// The name of your service.
        /// </param>
        /// <param name='deploymentName'>
        /// The name of the deployment.
        /// </param>
        /// <param name='roleName'>
        /// The name of the role to delete the data disk from.
        /// </param>
        /// <param name='logicalUnitNumber'>
        /// The logical unit number of the disk.
        /// </param>
        /// <param name='deleteFromStorage'>
        /// Optional. Specifies that the source blob for the disk should also
        /// be deleted from storage.
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
        public static Task<ComputeOperationStatusResponse> DeleteDataDiskAsync(this IVirtualMachineDiskOperations operations, string serviceName, string deploymentName, string roleName, int logicalUnitNumber, bool deleteFromStorage)
        {
            return operations.DeleteDataDiskAsync(serviceName, deploymentName, roleName, logicalUnitNumber, deleteFromStorage, CancellationToken.None);
        }
        
        /// <summary>
        /// The Delete Disk operation deletes the specified data or operating
        /// system disk from your image repository.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157200.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='diskName'>
        /// The name of the disk to delete.
        /// </param>
        /// <param name='deleteFromStorage'>
        /// Optional. Specifies that the source blob for the disk should also
        /// be deleted from storage.
        /// </param>
        /// <returns>
        /// A standard service response including an HTTP status code and
        /// request ID.
        /// </returns>
        public static OperationResponse DeleteDisk(this IVirtualMachineDiskOperations operations, string diskName, bool deleteFromStorage)
        {
            try
            {
                return operations.DeleteDiskAsync(diskName, deleteFromStorage).Result;
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
        /// The Delete Disk operation deletes the specified data or operating
        /// system disk from your image repository.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157200.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='diskName'>
        /// The name of the disk to delete.
        /// </param>
        /// <param name='deleteFromStorage'>
        /// Optional. Specifies that the source blob for the disk should also
        /// be deleted from storage.
        /// </param>
        /// <returns>
        /// A standard service response including an HTTP status code and
        /// request ID.
        /// </returns>
        public static Task<OperationResponse> DeleteDiskAsync(this IVirtualMachineDiskOperations operations, string diskName, bool deleteFromStorage)
        {
            return operations.DeleteDiskAsync(diskName, deleteFromStorage, CancellationToken.None);
        }
        
        /// <summary>
        /// The Get Data Disk operation retrieves the specified data disk from
        /// a virtual machine.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157180.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='serviceName'>
        /// The name of your service.
        /// </param>
        /// <param name='deploymentName'>
        /// The name of the deployment.
        /// </param>
        /// <param name='roleName'>
        /// The name of the role.
        /// </param>
        /// <param name='logicalUnitNumber'>
        /// The logical unit number of the disk.
        /// </param>
        /// <returns>
        /// The Get Data Disk operation response.
        /// </returns>
        public static VirtualMachineDiskGetDataDiskResponse GetDataDisk(this IVirtualMachineDiskOperations operations, string serviceName, string deploymentName, string roleName, int logicalUnitNumber)
        {
            try
            {
                return operations.GetDataDiskAsync(serviceName, deploymentName, roleName, logicalUnitNumber).Result;
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
        /// The Get Data Disk operation retrieves the specified data disk from
        /// a virtual machine.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157180.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='serviceName'>
        /// The name of your service.
        /// </param>
        /// <param name='deploymentName'>
        /// The name of the deployment.
        /// </param>
        /// <param name='roleName'>
        /// The name of the role.
        /// </param>
        /// <param name='logicalUnitNumber'>
        /// The logical unit number of the disk.
        /// </param>
        /// <returns>
        /// The Get Data Disk operation response.
        /// </returns>
        public static Task<VirtualMachineDiskGetDataDiskResponse> GetDataDiskAsync(this IVirtualMachineDiskOperations operations, string serviceName, string deploymentName, string roleName, int logicalUnitNumber)
        {
            return operations.GetDataDiskAsync(serviceName, deploymentName, roleName, logicalUnitNumber, CancellationToken.None);
        }
        
        /// <summary>
        /// The Get Disk operation retrieves a disk from the user image
        /// repository. The disk can be an operating system disk or a data
        /// disk.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157178.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='diskName'>
        /// The name of the disk.
        /// </param>
        /// <returns>
        /// A virtual machine disk associated with your subscription.
        /// </returns>
        public static VirtualMachineDiskGetDiskResponse GetDisk(this IVirtualMachineDiskOperations operations, string diskName)
        {
            try
            {
                return operations.GetDiskAsync(diskName).Result;
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
        /// The Get Disk operation retrieves a disk from the user image
        /// repository. The disk can be an operating system disk or a data
        /// disk.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157178.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='diskName'>
        /// The name of the disk.
        /// </param>
        /// <returns>
        /// A virtual machine disk associated with your subscription.
        /// </returns>
        public static Task<VirtualMachineDiskGetDiskResponse> GetDiskAsync(this IVirtualMachineDiskOperations operations, string diskName)
        {
            return operations.GetDiskAsync(diskName, CancellationToken.None);
        }
        
        /// <summary>
        /// The List Disks operation retrieves a list of the disks in your
        /// image repository.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157176.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <returns>
        /// The List Disks operation response.
        /// </returns>
        public static VirtualMachineDiskListResponse ListDisks(this IVirtualMachineDiskOperations operations)
        {
            try
            {
                return operations.ListDisksAsync().Result;
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
        /// The List Disks operation retrieves a list of the disks in your
        /// image repository.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157176.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <returns>
        /// The List Disks operation response.
        /// </returns>
        public static Task<VirtualMachineDiskListResponse> ListDisksAsync(this IVirtualMachineDiskOperations operations)
        {
            return operations.ListDisksAsync(CancellationToken.None);
        }
        
        /// <summary>
        /// The Update Data Disk operation updates the specified data disk
        /// attached to the specified virtual machine.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157190.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='serviceName'>
        /// The name of your service.
        /// </param>
        /// <param name='deploymentName'>
        /// The name of the deployment.
        /// </param>
        /// <param name='roleName'>
        /// The name of the role to add the data disk to.
        /// </param>
        /// <param name='logicalUnitNumber'>
        /// The logical unit number of the disk.
        /// </param>
        /// <param name='parameters'>
        /// Parameters supplied to the Update Virtual Machine Data Disk
        /// operation.
        /// </param>
        /// <returns>
        /// A standard service response including an HTTP status code and
        /// request ID.
        /// </returns>
        public static OperationResponse UpdateDataDisk(this IVirtualMachineDiskOperations operations, string serviceName, string deploymentName, string roleName, int logicalUnitNumber, VirtualMachineDiskUpdateDataDiskParameters parameters)
        {
            try
            {
                return operations.UpdateDataDiskAsync(serviceName, deploymentName, roleName, logicalUnitNumber, parameters).Result;
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
        /// The Update Data Disk operation updates the specified data disk
        /// attached to the specified virtual machine.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157190.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='serviceName'>
        /// The name of your service.
        /// </param>
        /// <param name='deploymentName'>
        /// The name of the deployment.
        /// </param>
        /// <param name='roleName'>
        /// The name of the role to add the data disk to.
        /// </param>
        /// <param name='logicalUnitNumber'>
        /// The logical unit number of the disk.
        /// </param>
        /// <param name='parameters'>
        /// Parameters supplied to the Update Virtual Machine Data Disk
        /// operation.
        /// </param>
        /// <returns>
        /// A standard service response including an HTTP status code and
        /// request ID.
        /// </returns>
        public static Task<OperationResponse> UpdateDataDiskAsync(this IVirtualMachineDiskOperations operations, string serviceName, string deploymentName, string roleName, int logicalUnitNumber, VirtualMachineDiskUpdateDataDiskParameters parameters)
        {
            return operations.UpdateDataDiskAsync(serviceName, deploymentName, roleName, logicalUnitNumber, parameters, CancellationToken.None);
        }
        
        /// <summary>
        /// The Add Disk operation adds a disk to the user image repository.
        /// The disk can be an operating system disk or a data disk.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157178.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='diskName'>
        /// The name of the disk being updated.
        /// </param>
        /// <param name='parameters'>
        /// Parameters supplied to the Update Virtual Machine Disk operation.
        /// </param>
        /// <returns>
        /// A virtual machine disk associated with your subscription.
        /// </returns>
        public static VirtualMachineDiskUpdateDiskResponse UpdateDisk(this IVirtualMachineDiskOperations operations, string diskName, VirtualMachineDiskUpdateDiskParameters parameters)
        {
            try
            {
                return operations.UpdateDiskAsync(diskName, parameters).Result;
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
        /// The Add Disk operation adds a disk to the user image repository.
        /// The disk can be an operating system disk or a data disk.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/jj157178.aspx
        /// for more information)
        /// </summary>
        /// <param name='operations'>
        /// Reference to the
        /// Microsoft.WindowsAzure.Management.Compute.IVirtualMachineDiskOperations.
        /// </param>
        /// <param name='diskName'>
        /// The name of the disk being updated.
        /// </param>
        /// <param name='parameters'>
        /// Parameters supplied to the Update Virtual Machine Disk operation.
        /// </param>
        /// <returns>
        /// A virtual machine disk associated with your subscription.
        /// </returns>
        public static Task<VirtualMachineDiskUpdateDiskResponse> UpdateDiskAsync(this IVirtualMachineDiskOperations operations, string diskName, VirtualMachineDiskUpdateDiskParameters parameters)
        {
            return operations.UpdateDiskAsync(diskName, parameters, CancellationToken.None);
        }
    }
}
