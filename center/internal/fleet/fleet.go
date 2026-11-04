// SPDX-License-Identifier: AGPL-3.0-only

// Package fleet is node enrollment (AF-CTR-04; ArcForges-Design AD-0021 sections 5, 10 and 13a): the enrolled nodes of an account
// (fleet.node), the browser sign-in (signin.go), the device-code sign-in (device.go), the one enrollment function both sign-in flows call (Enroll), the node's refresh,
// report and sign-out, and the device revocation's cascade participant for nodes. Enrollment is an account and device operation and is never gated. The Connect
// handlers (package fleetapi) and the pages call these functions in process, so the API and the pages share one set of rules,
// buckets and audit events.
//
// One global lock order (cloud-1, SEC-12): a sign-in flow row (a browser flow, fleet.node_sign_in, or a device authorization,
// fleet.device_authorization; taken by the flow's own transaction, E1b and E2), identity.user,
// device.device, device.installation, the identity.session rows, fleet.node. It is device.Revoke's order (device, installation,
// sessions, then the participants, so fleet.node last) with the flow row and the account in front. The writers of these rows that
// lock more than one of them take them in this order:
//
//   - Enroll locks the account (FOR UPDATE: it also makes the node cap race-free), then, for a node that is live in the account, its
//     device (re-checking that it is not revoked) and installation, then the approving session (FOR SHARE, in the session slot: an
//     approval never outlives a remediation that committed first), then supersedes the installation's sessions, then locks the node
//     row and re-reads it. A node without a live row gets new rows, inserted after the locks; their only waits are unique-index waits,
//     answered as store contention.
//   - The browser sign-in (signin.go): BeginNodeSignIn locks the node ID's pending flows that present its key, in flow ID order (the
//     one order of every writer that locks several flow rows), and inserts its flow; GetNodeSignInFlow marks one PENDING flow row;
//     ApproveNodeSignIn locks the flow row, then (approving) the account through identity.ConsumeEvidence and the proved challenge;
//     CompleteNodeSignIn locks the flow row and then calls Enroll, whose locks follow, or (a reuse) revokes the delivered family's
//     sessions. The foreign keys of the review mark, the approval and the denial take FOR KEY SHARE on the deciding account (and, for
//     an approval, on its session) after the flow row; no writer that holds an account or a session FOR UPDATE then waits for a flow
//     row, so they close no cycle.
//   - The device-code sign-in (device.go): StartDeviceAuthorization locks the node ID's pending authorizations that present its key,
//     in authorization ID order (the one order of every writer that locks several authorization rows), and inserts its
//     authorization; LookupDeviceCode locks one authorization row (its review's foreign key then takes FOR KEY SHARE on the account);
//     ApproveDeviceCode, after its command receipt row, locks the authorization row, then (approving) the account through
//     identity.ConsumeEvidenceFor and the proved challenge, and its update's foreign keys take FOR KEY SHARE on the account and the
//     approving session; PollDeviceAuthorization locks the authorization row and then calls Enroll, whose locks follow, or (a reuse)
//     revokes the delivered family's sessions. Lookup and Approve give the entry budgets back (the platform.rate_limit rows, the
//     account's then the network's) after every row of the order and before the audit chain head; every other user of those rows locks
//     one in its own transaction, except the give-back of an entry outside its decision, which takes the same two in the same order. No writer locks a device authorization and then a browser flow; only the account participants
//     lock both, the browser flows first.
//   - ReportNodeInfo locks the device only when it renames it, then the installation, then the node row.
//   - RefreshNodeSession locks the session row (session.Refresh), then updates the node row.
//   - RevokeAllSessions and RemoveAuthIdentity run the account participants first: ApprovalParticipant locks the account's browser
//     flows, then DeviceApprovalParticipant its device authorizations (each in ID order), before the evidence locks the account.
//   - The account's step-up evidence path (identity.ConsumeEvidence: RevokeSession of another session, RevokeAllSessions,
//     RemoveAuthIdentity, DeviceService.Revoke of another device) locks the account first; device.Revoke then takes the device,
//     installations, sessions and, through the participant, the node rows.
//   - The operator's admin revoke-sessions and admin revoke-device lock the accounts first (revoke-sessions FOR NO KEY UPDATE, every
//     account in account order for --all).
//
// Two accounts in one transaction: the AF-CTR-03 operator grant (entitlement.Operator) locks its caller's account FOR UPDATE and
// then inserts rows of the target account, whose foreign keys take FOR KEY SHARE on the target's row; that lock conflicts only with
// FOR UPDATE, which no multi-account writer takes, so it never closes a cycle with revoke-sessions --all. Every other writer of
// identity.user rows locks one account (see docs/center-fleet.md).
//
// The writers that lock fewer rows skip slots: SignOutNode, a sign-out of the caller's own session and a browser session's renewal
// touch one session row; the own-device DeviceService.Revoke takes no account lock and starts at the device; a step-up proof and the
// session upgrade lock the proving session. One writer goes back: a sign-in (device.EnsureNative, EnsureBrowser, AF-CTR-03 code)
// locks its installation and its device in one statement, the installation first, and then inserts a session. It meets a writer of
// the order only on the same installation (device.Revoke of its device; Enroll or ReportNodeInfo only when a native claim names a
// node's installation ID, refused after the lock); PostgreSQL breaks such a deadlock, the services retry it as contention (the
// operator's revoke-device runs once and is run again). Reordering it is routed to a later Cloud change of the device package.
// docs/center-fleet.md lists them.
//
// In every transaction a command receipt (when there is one) is the first row written and the audit chain head the last.
package fleet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"regexp"
	"strings"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/device"
)

// MaxVersionLength bounds a node version (EnrollingNodeInfo.version: SemVer 2.0.0, at most 128 characters).
const MaxVersionLength = 128

// semVer is the SemVer 2.0.0 grammar (semver.org), build metadata included.
var semVer = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)` +
	`(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?` +
	`(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

// ValidNodeVersion is the one validator of a node's version (cloud-11; BeginNodeSignIn, StartDeviceAuthorization, ReportNodeInfo and
// Enroll): at most 128 characters of SemVer 2.0.0. The center stores the canonical form, the text before the first '+' (build
// metadata removed, never mapped), which always satisfies the installation version rule of 0002; the raw value is never stored.
func ValidNodeVersion(raw string) (canonical string, ok bool) {
	if len(raw) > MaxVersionLength || !semVer.MatchString(raw) {
		return "", false
	}
	canonical, _, _ = strings.Cut(raw, "+")
	return canonical, true
}

// Platform is how a node's operating system is recorded: the OsFamily number on fleet.node, the device platform (mapped by name:
// WINDOWS is windows (1), LINUX is linux (3), never the OsFamily number, CR-04) and the installation's platform text.
type Platform struct {
	OS     int16
	Device device.Platform
	Text   string
}

// PlatformOf maps a node's OsFamily by name; any other value is not admitted.
func PlatformOf(os nodev1.OsFamily) (Platform, bool) {
	switch os {
	case nodev1.OsFamily_OS_FAMILY_WINDOWS:
		return Platform{OS: int16(nodev1.OsFamily_OS_FAMILY_WINDOWS), Device: device.PlatformWindows, Text: "windows"}, true
	case nodev1.OsFamily_OS_FAMILY_LINUX:
		return Platform{OS: int16(nodev1.OsFamily_OS_FAMILY_LINUX), Device: device.PlatformLinux, Text: "linux"}, true
	}
	return Platform{}, false
}

// OSName is the audit name of a stored OsFamily number.
func OSName(os int16) string {
	switch nodev1.OsFamily(os) {
	case nodev1.OsFamily_OS_FAMILY_WINDOWS:
		return "windows"
	case nodev1.OsFamily_OS_FAMILY_LINUX:
		return "linux"
	}
	return "unknown"
}

// ArchOf admits the two CPU architectures (x64 1, arm64 2).
func ArchOf(arch nodev1.CpuArchitecture) (int16, bool) {
	switch arch {
	case nodev1.CpuArchitecture_CPU_ARCHITECTURE_X64, nodev1.CpuArchitecture_CPU_ARCHITECTURE_ARM64:
		return int16(arch), true
	}
	return 0, false
}

// ArchName is the audit name of a stored architecture.
func ArchName(arch int16) string {
	switch nodev1.CpuArchitecture(arch) {
	case nodev1.CpuArchitecture_CPU_ARCHITECTURE_X64:
		return "x64"
	case nodev1.CpuArchitecture_CPU_ARCHITECTURE_ARM64:
		return "arm64"
	}
	return "unknown"
}

// NodeKeyLength is the length of a node public key: the PKIX SubjectPublicKeyInfo DER of an uncompressed ECDSA P-256 key.
const NodeKeyLength = 91

// ValidNodeKey admits a node public key: exactly the 91-byte PKIX DER of an ECDSA P-256 key, in its canonical encoding (the key
// marshals back to the same bytes).
func ValidNodeKey(der []byte) bool {
	if len(der) != NodeKeyLength {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return false
	}
	again, err := x509.MarshalPKIXPublicKey(key)
	return err == nil && string(again) == string(der)
}

// Fingerprint is a node key's fingerprint as people compare it (KEY-01, C0 E-6): the first 10 bytes of SHA-256 over the PKIX DER, in
// upper-case hexadecimal, in five groups of four separated by '-'.
func Fingerprint(der []byte) string {
	digest := sha256.Sum256(der)
	text := strings.ToUpper(hex.EncodeToString(digest[:10]))
	return text[0:4] + "-" + text[4:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20]
}

// NodeInfo is a node as it describes itself (EnrollingNodeInfo), validated: the name by device.ValidNodeName, the canonical
// version, the platform and architecture mapped by name.
type NodeInfo struct {
	Name     string
	Platform Platform
	Arch     int16
	Version  string
}

// ParseNodeInfo validates a node's description field by field (VALIDATION/invalid_argument names the first field that fails, with
// the rule length, pattern or not_admitted). A role other than HOST or unspecified and any host_node_id are refused (AD-0018: the
// GUEST role is retired).
func ParseNodeInfo(info *fleetv1.EnrollingNodeInfo) (NodeInfo, error) {
	name := info.GetName()
	switch {
	case device.NameTooLong(name):
		return NodeInfo{}, arc.InvalidArgument("node.name", "length")
	case !device.ValidNodeName(name):
		return NodeInfo{}, arc.InvalidArgument("node.name", "pattern")
	}
	platform, ok := PlatformOf(info.GetOs())
	if !ok {
		return NodeInfo{}, arc.InvalidArgument("node.os", "not_admitted")
	}
	arch, ok := ArchOf(info.GetArch())
	if !ok {
		return NodeInfo{}, arc.InvalidArgument("node.arch", "not_admitted")
	}
	version, ok := ValidNodeVersion(info.GetVersion())
	switch {
	case len(info.GetVersion()) > MaxVersionLength:
		return NodeInfo{}, arc.InvalidArgument("node.version", "length")
	case !ok:
		return NodeInfo{}, arc.InvalidArgument("node.version", "pattern")
	}
	if role := info.GetRole(); role != nodev1.NodeRole_NODE_ROLE_UNSPECIFIED && role != nodev1.NodeRole_NODE_ROLE_HOST {
		return NodeInfo{}, arc.InvalidArgument("node.role", "not_admitted")
	}
	if len(info.GetHostNodeId().GetValue()) != 0 {
		return NodeInfo{}, arc.InvalidArgument("node.host_node_id", "not_admitted")
	}
	return NodeInfo{Name: name, Platform: platform, Arch: arch, Version: version}, nil
}
