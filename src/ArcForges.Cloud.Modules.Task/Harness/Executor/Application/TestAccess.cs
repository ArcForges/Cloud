// SPDX-License-Identifier: AGPL-3.0-only
// The executor and its store stay internal until a host route is registered for the wake; the Cloud test assembly reaches them here.
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("ArcForges.Cloud.Tests")]
