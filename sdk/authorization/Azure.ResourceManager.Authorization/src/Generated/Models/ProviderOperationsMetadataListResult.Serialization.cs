// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.Authorization.Models
{
    public partial class ProviderOperationsMetadataListResult
    {
        internal static ProviderOperationsMetadataListResult DeserializeProviderOperationsMetadataListResult(JsonElement element)
        {
            Optional<IReadOnlyList<ProviderOperationsMetadata>> value = default;
            Optional<string> nextLink = default;
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("value"))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        property.ThrowNonNullablePropertyIsNull();
                        continue;
                    }
                    List<ProviderOperationsMetadata> array = new List<ProviderOperationsMetadata>();
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        array.Add(ProviderOperationsMetadata.DeserializeProviderOperationsMetadata(item));
                    }
                    value = array;
                    continue;
                }
                if (property.NameEquals("nextLink"))
                {
                    nextLink = property.Value.GetString();
                    continue;
                }
            }
            return new ProviderOperationsMetadataListResult(Optional.ToList(value), nextLink.Value);
        }
    }
}
