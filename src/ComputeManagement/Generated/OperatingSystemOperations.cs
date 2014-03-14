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
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.WindowsAzure;
using Microsoft.WindowsAzure.Common;
using Microsoft.WindowsAzure.Common.Internals;
using Microsoft.WindowsAzure.Management.Compute;
using Microsoft.WindowsAzure.Management.Compute.Models;

namespace Microsoft.WindowsAzure.Management.Compute
{
    /// <summary>
    /// Operations for determining the version of the Windows Azure Guest
    /// Operating System on which your service is running.  (see
    /// http://msdn.microsoft.com/en-us/library/windowsazure/ff684169.aspx for
    /// more information)
    /// </summary>
    internal partial class OperatingSystemOperations : IServiceOperations<ComputeManagementClient>, Microsoft.WindowsAzure.Management.Compute.IOperatingSystemOperations
    {
        /// <summary>
        /// Initializes a new instance of the OperatingSystemOperations class.
        /// </summary>
        /// <param name='client'>
        /// Reference to the service client.
        /// </param>
        internal OperatingSystemOperations(ComputeManagementClient client)
        {
            this._client = client;
        }
        
        private ComputeManagementClient _client;
        
        /// <summary>
        /// Gets a reference to the
        /// Microsoft.WindowsAzure.Management.Compute.ComputeManagementClient.
        /// </summary>
        public ComputeManagementClient Client
        {
            get { return this._client; }
        }
        
        /// <summary>
        /// The List Operating Systems operation lists the versions of the
        /// guest operating system that are currently available in Windows
        /// Azure. The 2010-10-28 version of List Operating Systems also
        /// indicates what family an operating system version belongs to.
        /// Currently Windows Azure supports two operating system families:
        /// the Windows Azure guest operating system that is substantially
        /// compatible with Windows Server 2008 SP2, and the Windows Azure
        /// guest operating system that is substantially compatible with
        /// Windows Server 2008 R2.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/ff684168.aspx
        /// for more information)
        /// </summary>
        /// <param name='cancellationToken'>
        /// Cancellation token.
        /// </param>
        /// <returns>
        /// The List Operating Systems operation response.
        /// </returns>
        public async System.Threading.Tasks.Task<Microsoft.WindowsAzure.Management.Compute.Models.OperatingSystemListResponse> ListAsync(CancellationToken cancellationToken)
        {
            // Validate
            
            // Tracing
            bool shouldTrace = CloudContext.Configuration.Tracing.IsEnabled;
            string invocationId = null;
            if (shouldTrace)
            {
                invocationId = Tracing.NextInvocationId.ToString();
                Dictionary<string, object> tracingParameters = new Dictionary<string, object>();
                Tracing.Enter(invocationId, this, "ListAsync", tracingParameters);
            }
            
            // Construct URL
            string url = new Uri(this.Client.BaseUri, "/").AbsoluteUri + this.Client.Credentials.SubscriptionId + "/operatingsystems";
            
            // Create HTTP transport objects
            HttpRequestMessage httpRequest = null;
            try
            {
                httpRequest = new HttpRequestMessage();
                httpRequest.Method = HttpMethod.Get;
                httpRequest.RequestUri = new Uri(url);
                
                // Set Headers
                httpRequest.Headers.Add("x-ms-version", "2014-04-01");
                
                // Set Credentials
                cancellationToken.ThrowIfCancellationRequested();
                await this.Client.Credentials.ProcessHttpRequestAsync(httpRequest, cancellationToken).ConfigureAwait(false);
                
                // Send Request
                HttpResponseMessage httpResponse = null;
                try
                {
                    if (shouldTrace)
                    {
                        Tracing.SendRequest(invocationId, httpRequest);
                    }
                    cancellationToken.ThrowIfCancellationRequested();
                    httpResponse = await this.Client.HttpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);
                    if (shouldTrace)
                    {
                        Tracing.ReceiveResponse(invocationId, httpResponse);
                    }
                    HttpStatusCode statusCode = httpResponse.StatusCode;
                    if (statusCode != HttpStatusCode.OK)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        CloudException ex = CloudException.Create(httpRequest, null, httpResponse, await httpResponse.Content.ReadAsStringAsync().ConfigureAwait(false), CloudExceptionType.Xml);
                        if (shouldTrace)
                        {
                            Tracing.Error(invocationId, ex);
                        }
                        throw ex;
                    }
                    
                    // Create Result
                    OperatingSystemListResponse result = null;
                    // Deserialize Response
                    cancellationToken.ThrowIfCancellationRequested();
                    string responseContent = await httpResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
                    result = new OperatingSystemListResponse();
                    XDocument responseDoc = XDocument.Parse(responseContent);
                    
                    XElement operatingSystemsSequenceElement = responseDoc.Element(XName.Get("OperatingSystems", "http://schemas.microsoft.com/windowsazure"));
                    if (operatingSystemsSequenceElement != null && operatingSystemsSequenceElement.IsEmpty == false)
                    {
                        foreach (XElement operatingSystemsElement in operatingSystemsSequenceElement.Elements(XName.Get("OperatingSystem", "http://schemas.microsoft.com/windowsazure")))
                        {
                            OperatingSystemListResponse.OperatingSystem operatingSystemInstance = new OperatingSystemListResponse.OperatingSystem();
                            result.OperatingSystems.Add(operatingSystemInstance);
                            
                            XElement versionElement = operatingSystemsElement.Element(XName.Get("Version", "http://schemas.microsoft.com/windowsazure"));
                            if (versionElement != null && versionElement.IsEmpty == false)
                            {
                                string versionInstance = versionElement.Value;
                                operatingSystemInstance.Version = versionInstance;
                            }
                            
                            XElement labelElement = operatingSystemsElement.Element(XName.Get("Label", "http://schemas.microsoft.com/windowsazure"));
                            if (labelElement != null && labelElement.IsEmpty == false)
                            {
                                string labelInstance = TypeConversion.FromBase64String(labelElement.Value);
                                operatingSystemInstance.Label = labelInstance;
                            }
                            
                            XElement isDefaultElement = operatingSystemsElement.Element(XName.Get("IsDefault", "http://schemas.microsoft.com/windowsazure"));
                            if (isDefaultElement != null && isDefaultElement.IsEmpty == false)
                            {
                                bool isDefaultInstance = bool.Parse(isDefaultElement.Value);
                                operatingSystemInstance.IsDefault = isDefaultInstance;
                            }
                            
                            XElement isActiveElement = operatingSystemsElement.Element(XName.Get("IsActive", "http://schemas.microsoft.com/windowsazure"));
                            if (isActiveElement != null && isActiveElement.IsEmpty == false)
                            {
                                bool isActiveInstance = bool.Parse(isActiveElement.Value);
                                operatingSystemInstance.IsActive = isActiveInstance;
                            }
                            
                            XElement familyElement = operatingSystemsElement.Element(XName.Get("Family", "http://schemas.microsoft.com/windowsazure"));
                            if (familyElement != null && familyElement.IsEmpty == false)
                            {
                                int familyInstance = int.Parse(familyElement.Value, CultureInfo.InvariantCulture);
                                operatingSystemInstance.Family = familyInstance;
                            }
                            
                            XElement familyLabelElement = operatingSystemsElement.Element(XName.Get("FamilyLabel", "http://schemas.microsoft.com/windowsazure"));
                            if (familyLabelElement != null && familyLabelElement.IsEmpty == false)
                            {
                                string familyLabelInstance = TypeConversion.FromBase64String(familyLabelElement.Value);
                                operatingSystemInstance.FamilyLabel = familyLabelInstance;
                            }
                        }
                    }
                    
                    result.StatusCode = statusCode;
                    if (httpResponse.Headers.Contains("x-ms-request-id"))
                    {
                        result.RequestId = httpResponse.Headers.GetValues("x-ms-request-id").FirstOrDefault();
                    }
                    
                    if (shouldTrace)
                    {
                        Tracing.Exit(invocationId, result);
                    }
                    return result;
                }
                finally
                {
                    if (httpResponse != null)
                    {
                        httpResponse.Dispose();
                    }
                }
            }
            finally
            {
                if (httpRequest != null)
                {
                    httpRequest.Dispose();
                }
            }
        }
        
        /// <summary>
        /// The List OS Families operation lists the guest operating system
        /// families available in Windows Azure, and also lists the operating
        /// system versions available for each family. Currently Windows Azure
        /// supports two operating system families: the Windows Azure guest
        /// operating system that is substantially compatible with Windows
        /// Server 2008 SP2, and the Windows Azure guest operating system that
        /// is substantially compatible with Windows Server 2008 R2.  (see
        /// http://msdn.microsoft.com/en-us/library/windowsazure/gg441291.aspx
        /// for more information)
        /// </summary>
        /// <param name='cancellationToken'>
        /// Cancellation token.
        /// </param>
        /// <returns>
        /// The List Operating System Families operation response.
        /// </returns>
        public async System.Threading.Tasks.Task<Microsoft.WindowsAzure.Management.Compute.Models.OperatingSystemListFamiliesResponse> ListFamiliesAsync(CancellationToken cancellationToken)
        {
            // Validate
            
            // Tracing
            bool shouldTrace = CloudContext.Configuration.Tracing.IsEnabled;
            string invocationId = null;
            if (shouldTrace)
            {
                invocationId = Tracing.NextInvocationId.ToString();
                Dictionary<string, object> tracingParameters = new Dictionary<string, object>();
                Tracing.Enter(invocationId, this, "ListFamiliesAsync", tracingParameters);
            }
            
            // Construct URL
            string url = new Uri(this.Client.BaseUri, "/").AbsoluteUri + this.Client.Credentials.SubscriptionId + "/operatingsystemfamilies";
            
            // Create HTTP transport objects
            HttpRequestMessage httpRequest = null;
            try
            {
                httpRequest = new HttpRequestMessage();
                httpRequest.Method = HttpMethod.Get;
                httpRequest.RequestUri = new Uri(url);
                
                // Set Headers
                httpRequest.Headers.Add("x-ms-version", "2014-04-01");
                
                // Set Credentials
                cancellationToken.ThrowIfCancellationRequested();
                await this.Client.Credentials.ProcessHttpRequestAsync(httpRequest, cancellationToken).ConfigureAwait(false);
                
                // Send Request
                HttpResponseMessage httpResponse = null;
                try
                {
                    if (shouldTrace)
                    {
                        Tracing.SendRequest(invocationId, httpRequest);
                    }
                    cancellationToken.ThrowIfCancellationRequested();
                    httpResponse = await this.Client.HttpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);
                    if (shouldTrace)
                    {
                        Tracing.ReceiveResponse(invocationId, httpResponse);
                    }
                    HttpStatusCode statusCode = httpResponse.StatusCode;
                    if (statusCode != HttpStatusCode.OK)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        CloudException ex = CloudException.Create(httpRequest, null, httpResponse, await httpResponse.Content.ReadAsStringAsync().ConfigureAwait(false), CloudExceptionType.Xml);
                        if (shouldTrace)
                        {
                            Tracing.Error(invocationId, ex);
                        }
                        throw ex;
                    }
                    
                    // Create Result
                    OperatingSystemListFamiliesResponse result = null;
                    // Deserialize Response
                    cancellationToken.ThrowIfCancellationRequested();
                    string responseContent = await httpResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
                    result = new OperatingSystemListFamiliesResponse();
                    XDocument responseDoc = XDocument.Parse(responseContent);
                    
                    XElement operatingSystemFamiliesSequenceElement = responseDoc.Element(XName.Get("OperatingSystemFamilies", "http://schemas.microsoft.com/windowsazure"));
                    if (operatingSystemFamiliesSequenceElement != null && operatingSystemFamiliesSequenceElement.IsEmpty == false)
                    {
                        foreach (XElement operatingSystemFamiliesElement in operatingSystemFamiliesSequenceElement.Elements(XName.Get("OperatingSystemFamily", "http://schemas.microsoft.com/windowsazure")))
                        {
                            OperatingSystemListFamiliesResponse.OperatingSystemFamily operatingSystemFamilyInstance = new OperatingSystemListFamiliesResponse.OperatingSystemFamily();
                            result.OperatingSystemFamilies.Add(operatingSystemFamilyInstance);
                            
                            XElement nameElement = operatingSystemFamiliesElement.Element(XName.Get("Name", "http://schemas.microsoft.com/windowsazure"));
                            if (nameElement != null && nameElement.IsEmpty == false)
                            {
                                int nameInstance = int.Parse(nameElement.Value, CultureInfo.InvariantCulture);
                                operatingSystemFamilyInstance.Name = nameInstance;
                            }
                            
                            XElement labelElement = operatingSystemFamiliesElement.Element(XName.Get("Label", "http://schemas.microsoft.com/windowsazure"));
                            if (labelElement != null && labelElement.IsEmpty == false)
                            {
                                string labelInstance = TypeConversion.FromBase64String(labelElement.Value);
                                operatingSystemFamilyInstance.Label = labelInstance;
                            }
                            
                            XElement operatingSystemsSequenceElement = operatingSystemFamiliesElement.Element(XName.Get("OperatingSystems", "http://schemas.microsoft.com/windowsazure"));
                            if (operatingSystemsSequenceElement != null && operatingSystemsSequenceElement.IsEmpty == false)
                            {
                                foreach (XElement operatingSystemsElement in operatingSystemsSequenceElement.Elements(XName.Get("OperatingSystem", "http://schemas.microsoft.com/windowsazure")))
                                {
                                    OperatingSystemListFamiliesResponse.OperatingSystem operatingSystemInstance = new OperatingSystemListFamiliesResponse.OperatingSystem();
                                    operatingSystemFamilyInstance.OperatingSystems.Add(operatingSystemInstance);
                                    
                                    XElement versionElement = operatingSystemsElement.Element(XName.Get("Version", "http://schemas.microsoft.com/windowsazure"));
                                    if (versionElement != null && versionElement.IsEmpty == false)
                                    {
                                        string versionInstance = versionElement.Value;
                                        operatingSystemInstance.Version = versionInstance;
                                    }
                                    
                                    XElement labelElement2 = operatingSystemsElement.Element(XName.Get("Label", "http://schemas.microsoft.com/windowsazure"));
                                    if (labelElement2 != null && labelElement2.IsEmpty == false)
                                    {
                                        string labelInstance2 = TypeConversion.FromBase64String(labelElement2.Value);
                                        operatingSystemInstance.Label = labelInstance2;
                                    }
                                    
                                    XElement isDefaultElement = operatingSystemsElement.Element(XName.Get("IsDefault", "http://schemas.microsoft.com/windowsazure"));
                                    if (isDefaultElement != null && isDefaultElement.IsEmpty == false)
                                    {
                                        bool isDefaultInstance = bool.Parse(isDefaultElement.Value);
                                        operatingSystemInstance.IsDefault = isDefaultInstance;
                                    }
                                    
                                    XElement isActiveElement = operatingSystemsElement.Element(XName.Get("IsActive", "http://schemas.microsoft.com/windowsazure"));
                                    if (isActiveElement != null && isActiveElement.IsEmpty == false)
                                    {
                                        bool isActiveInstance = bool.Parse(isActiveElement.Value);
                                        operatingSystemInstance.IsActive = isActiveInstance;
                                    }
                                }
                            }
                        }
                    }
                    
                    result.StatusCode = statusCode;
                    if (httpResponse.Headers.Contains("x-ms-request-id"))
                    {
                        result.RequestId = httpResponse.Headers.GetValues("x-ms-request-id").FirstOrDefault();
                    }
                    
                    if (shouldTrace)
                    {
                        Tracing.Exit(invocationId, result);
                    }
                    return result;
                }
                finally
                {
                    if (httpResponse != null)
                    {
                        httpResponse.Dispose();
                    }
                }
            }
            finally
            {
                if (httpRequest != null)
                {
                    httpRequest.Dispose();
                }
            }
        }
    }
}
