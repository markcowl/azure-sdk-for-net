// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.Authorization.Models
{
    public partial class ProviderOperationsMetadata
    {
        internal static ProviderOperationsMetadata DeserializeProviderOperationsMetadata(JsonElement element)
        {
            Optional<string> id = default;
            Optional<string> name = default;
            Optional<string> type = default;
            Optional<string> displayName = default;
            Optional<IReadOnlyList<ResourceType>> resourceTypes = default;
            Optional<IReadOnlyList<ProviderOperation>> operations = default;
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("id"))
                {
                    id = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("name"))
                {
                    name = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("type"))
                {
                    type = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("displayName"))
                {
                    displayName = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("resourceTypes"))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        property.ThrowNonNullablePropertyIsNull();
                        continue;
                    }
                    List<ResourceType> array = new List<ResourceType>();
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        array.Add(ResourceType.DeserializeResourceType(item));
                    }
                    resourceTypes = array;
                    continue;
                }
                if (property.NameEquals("operations"))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        property.ThrowNonNullablePropertyIsNull();
                        continue;
                    }
                    List<ProviderOperation> array = new List<ProviderOperation>();
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        array.Add(ProviderOperation.DeserializeProviderOperation(item));
                    }
                    operations = array;
                    continue;
                }
            }
            return new ProviderOperationsMetadata(id.Value, name.Value, type.Value, displayName.Value, Optional.ToList(resourceTypes), Optional.ToList(operations));
        }
    }
}
