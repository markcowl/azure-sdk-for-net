//
// Copyright (c) Microsoft.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

using System;
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace Microsoft.Azure.Management.DataFactories
{
    internal static class Ensure
    {
        public static void IsNotNull<T>(T value, string name, string msg = null, [CallerMemberName]string method = "")
        {
            if (value == null)
            {
                if (msg == null)
                {
                    msg = string.Format(CultureInfo.InvariantCulture, "'{0}' may not be null in {1}", name, method);
                }

                throw new ArgumentNullException(name, msg);
            }
        }

        public static void IsNotNullOrEmpty(string value, string name, string msg = null, [CallerMemberName]string method = "")
        {
            if (string.IsNullOrEmpty(value))
            {
                if (msg == null)
                {
                    msg = string.Format(CultureInfo.InvariantCulture, "'{0}' may not be null or empty in {1}", name, method);
                }

                throw new ArgumentException(name, msg);
            }
        }

        public static void IsNotNullOperationException<T>(T value, string name)
        {
            if (value == null)
            {
                string msg = string.Format(
                    CultureInfo.InvariantCulture,
                    "'{0}' may not be null. Something went wrong getting the server response.",
                    name);

                throw new InvalidOperationException(msg);
            }
        }

        public static void IsNotNullNoStackTrace(object value, string name)
        {
            if (value == null)
            {
                throw new ArgumentNullException(name);
            } 
        }
    }
}
