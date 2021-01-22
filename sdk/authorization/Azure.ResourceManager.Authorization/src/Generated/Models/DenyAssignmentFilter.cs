// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

namespace Azure.ResourceManager.Authorization.Models
{
    /// <summary> Deny Assignments filter. </summary>
    internal partial class DenyAssignmentFilter
    {
        /// <summary> Initializes a new instance of DenyAssignmentFilter. </summary>
        internal DenyAssignmentFilter()
        {
        }

        /// <summary> Return deny assignment with specified name. </summary>
        public string DenyAssignmentName { get; }
        /// <summary> Return all deny assignments where the specified principal is listed in the principals list of deny assignments. </summary>
        public string PrincipalId { get; }
        /// <summary> Return all deny assignments where the specified principal is listed either in the principals list or exclude principals list of deny assignments. </summary>
        public string GdprExportPrincipalId { get; }
    }
}
