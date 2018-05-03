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
using Microsoft.Azure.Management.Automation.Models;

namespace Microsoft.Azure.Management.Automation.Models
{
    /// <summary>
    /// The parameters supplied to the create or update node configuration
    /// operation.
    /// </summary>
    public partial class DscNodeConfigurationCreateOrUpdateParameters
    {
        private DscConfigurationAssociationProperty _configuration;
        
        /// <summary>
        /// Required. Gets or sets the configuration of the node.
        /// </summary>
        public DscConfigurationAssociationProperty Configuration
        {
            get { return this._configuration; }
            set { this._configuration = value; }
        }
        
        private bool _incrementNodeConfigurationBuild;
        
        /// <summary>
        /// Optional. Gets or sets the if a new build version of
        /// NodeConfiguration is required.
        /// </summary>
        public bool IncrementNodeConfigurationBuild
        {
            get { return this._incrementNodeConfigurationBuild; }
            set { this._incrementNodeConfigurationBuild = value; }
        }
        
        private string _name;
        
        /// <summary>
        /// Required. Gets or sets the type of the parameter.
        /// </summary>
        public string Name
        {
            get { return this._name; }
            set { this._name = value; }
        }
        
        private ContentSource _source;
        
        /// <summary>
        /// Required. Gets or sets the source.
        /// </summary>
        public ContentSource Source
        {
            get { return this._source; }
            set { this._source = value; }
        }
        
        /// <summary>
        /// Initializes a new instance of the
        /// DscNodeConfigurationCreateOrUpdateParameters class.
        /// </summary>
        public DscNodeConfigurationCreateOrUpdateParameters()
        {
        }
        
        /// <summary>
        /// Initializes a new instance of the
        /// DscNodeConfigurationCreateOrUpdateParameters class with required
        /// arguments.
        /// </summary>
        public DscNodeConfigurationCreateOrUpdateParameters(ContentSource source, string name, DscConfigurationAssociationProperty configuration)
            : this()
        {
            if (source == null)
            {
                throw new ArgumentNullException("source");
            }
            if (name == null)
            {
                throw new ArgumentNullException("name");
            }
            if (configuration == null)
            {
                throw new ArgumentNullException("configuration");
            }
            this.Source = source;
            this.Name = name;
            this.Configuration = configuration;
        }
    }
}
