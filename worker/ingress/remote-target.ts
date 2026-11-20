// SPDX-License-Identifier: AGPL-3.0-only

import {
  remoteEnrollmentHeader,
  remoteGrantHeader,
  remoteGrantRevisionHeader,
  remoteNodeHeader,
} from "../tables/center-tables.generated.ts";

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const zeroUUID = "00000000-0000-0000-0000-000000000000";
const maximumRevision = 9223372036854775807n;

function targetUUID(value: string | null): string | null {
  if (value === null || value.length !== 36) return null;
  const canonical = value.toLowerCase();
  return uuidPattern.test(canonical) && canonical !== zeroUUID ? canonical : null;
}

/** Forward only the typed selection fields. The Center authenticates and authorizes the selection. */
export function forwardRemoteTarget(input: Headers, output: Headers): boolean {
  const node = targetUUID(input.get(remoteNodeHeader));
  const enrollment = targetUUID(input.get(remoteEnrollmentHeader));
  const grant = targetUUID(input.get(remoteGrantHeader));
  const revision = input.get(remoteGrantRevisionHeader);
  if (
    node === null ||
    enrollment === null ||
    grant === null ||
    revision === null ||
    !/^[1-9][0-9]{0,18}$/.test(revision) ||
    BigInt(revision) > maximumRevision
  ) {
    return false;
  }
  output.set(remoteNodeHeader, node);
  output.set(remoteEnrollmentHeader, enrollment);
  output.set(remoteGrantHeader, grant);
  output.set(remoteGrantRevisionHeader, revision);
  return true;
}
