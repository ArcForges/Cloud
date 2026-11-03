// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"regexp"
	"strings"
	"testing"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/device"
)

// installationAppVersion is 0002's installation_app_version rule: every canonical version must satisfy it.
var installationAppVersion = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)

// TestValidNodeVersion pins cloud-11: SemVer 2.0.0 of at most 128 characters, stored as the text before the first '+' (never
// mapped), which always satisfies the installation version rule; the .NET informational version with its commit is admitted.
func TestValidNodeVersion(t *testing.T) {
	for raw, want := range map[string]string{
		"0.1.0-dev+15d6717144468ce0be615e8538f858d29b0fed7d": "0.1.0-dev",
		"1.0.0+build.5":                     "1.0.0",
		"1.0.0-rc.1+x-y":                    "1.0.0-rc.1",
		"1.2.3":                             "1.2.3",
		"0.0.0-0.a.b-c.1":                   "0.0.0-0.a.b-c.1",
		"1.0.0-" + strings.Repeat("a", 122): "1.0.0-" + strings.Repeat("a", 122),
	} {
		canonical, ok := ValidNodeVersion(raw)
		if !ok || canonical != want || !installationAppVersion.MatchString(canonical) || strings.Contains(canonical, "+") {
			t.Errorf("%q: %q %v", raw, canonical, ok)
		}
	}
	for _, raw := range []string{"", "1.0", "v1.0.0", "1.0.0+", "1.0.0-", "01.0.0", "1.0.0+a..b", "1.0.0 +x", "1.0.0-01", "1.0.0+a+b",
		"1.0.0-" + strings.Repeat("a", 123), "\uff11.0.0", "1.0.0\n"} {
		if canonical, ok := ValidNodeVersion(raw); ok {
			t.Errorf("%q admitted as %q", raw, canonical)
		}
	}
}

func p256Key(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestNodeKeyVectors admits exactly the 91-byte PKIX DER of an uncompressed P-256 key: P-384, Ed25519, RSA, an X25519 key, a
// compressed point, a truncated key and trailing bytes are refused.
func TestNodeKeyVectors(t *testing.T) {
	good := p256Key(t)
	if len(good) != NodeKeyLength || !ValidNodeKey(good) {
		t.Fatalf("a P-256 key is refused: %d bytes", len(good))
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	edPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	x25519, _ := ecdh.X25519().GenerateKey(rand.Reader)
	refused := map[string][]byte{"trailing byte": append(append([]byte{}, good...), 0), "truncated": good[:90], "empty": nil}
	for name, public := range map[string]any{"P-384": &p384.PublicKey, "Ed25519": edPublic, "RSA": &rsaKey.PublicKey, "X25519": x25519.PublicKey()} {
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		refused[name] = der
	}
	// A compressed point: the same SubjectPublicKeyInfo prefix with the 33-byte compressed form (and its shorter lengths).
	// The uncompressed point is the DER's last 65 bytes (0x04 || X || Y); its compressed form is (0x02 | the parity of Y) || X.
	point := good[NodeKeyLength-65:]
	compressed := append([]byte{0x02 | point[64]&1}, point[1:33]...)
	refused["compressed"] = append(append([]byte{0x30, 0x39, 0x30, 0x13}, good[4:23]...), append([]byte{0x03, 0x22, 0x00}, compressed...)...)
	flipped := append([]byte{}, good...)
	flipped[90] ^= 0xff
	refused["a point not on the curve"] = flipped
	for name, der := range refused {
		if ValidNodeKey(der) {
			t.Errorf("%s admitted", name)
		}
	}
	if fingerprint := Fingerprint(good); !regexp.MustCompile(`^[0-9A-F]{4}(-[0-9A-F]{4}){4}$`).MatchString(fingerprint) {
		t.Fatalf("fingerprint %q", fingerprint)
	}
}

// TestPlatformOfMapsByName pins CR-04 and C0 freeze item 11: OsFamily LINUX (2) is the device platform linux (3), never macos (2);
// WINDOWS is windows (1); nothing else is admitted.
func TestPlatformOfMapsByName(t *testing.T) {
	linux, ok := PlatformOf(nodev1.OsFamily_OS_FAMILY_LINUX)
	if !ok || linux.OS != 2 || linux.Device != device.PlatformLinux || linux.Device == device.PlatformMacOS || linux.Text != "linux" {
		t.Fatalf("linux %+v", linux)
	}
	windows, ok := PlatformOf(nodev1.OsFamily_OS_FAMILY_WINDOWS)
	if !ok || windows.OS != 1 || windows.Device != device.PlatformWindows || windows.Text != "windows" {
		t.Fatalf("windows %+v", windows)
	}
	for _, os := range []nodev1.OsFamily{nodev1.OsFamily_OS_FAMILY_UNSPECIFIED, nodev1.OsFamily(3)} {
		if _, ok := PlatformOf(os); ok {
			t.Errorf("%v admitted", os)
		}
	}
	if OSName(2) != "linux" || ArchName(2) != "arm64" || ArchName(1) != "x64" {
		t.Fatal("audit names")
	}
}

// TestParseNodeInfo names the first failing field with its rule.
func TestParseNodeInfo(t *testing.T) {
	valid := func() *fleetv1.EnrollingNodeInfo {
		return &fleetv1.EnrollingNodeInfo{NodeId: &foundationv1.Id{Value: make([]byte, 16)}, Name: proto.String("buildbox"), Os: nodev1.OsFamily_OS_FAMILY_LINUX.Enum(),
			Arch: nodev1.CpuArchitecture_CPU_ARCHITECTURE_X64.Enum(), Version: proto.String("0.1.0-dev+abc")}
	}
	info, err := ParseNodeInfo(valid())
	if err != nil || info.Version != "0.1.0-dev" || info.Platform.Device != device.PlatformLinux || info.Arch != 1 || info.Name != "buildbox" {
		t.Fatalf("%+v %v", info, err)
	}
	for want, mutate := range map[string]func(*fleetv1.EnrollingNodeInfo){
		"node.name: length":               func(i *fleetv1.EnrollingNodeInfo) { i.Name = proto.String(strings.Repeat("n", 65)) },
		"node.name: pattern":              func(i *fleetv1.EnrollingNodeInfo) { i.Name = proto.String("evil\u202egnp") },
		"node.os: not_admitted":           func(i *fleetv1.EnrollingNodeInfo) { i.Os = nil },
		"node.arch: not_admitted":         func(i *fleetv1.EnrollingNodeInfo) { i.Arch = nodev1.CpuArchitecture(7).Enum() },
		"node.version: length":            func(i *fleetv1.EnrollingNodeInfo) { i.Version = proto.String("1.0.0-" + strings.Repeat("a", 123)) },
		"node.version: pattern":           func(i *fleetv1.EnrollingNodeInfo) { i.Version = proto.String("1.0") },
		"node.role: not_admitted":         func(i *fleetv1.EnrollingNodeInfo) { i.Role = nodev1.NodeRole_NODE_ROLE_GUEST.Enum() },
		"node.host_node_id: not_admitted": func(i *fleetv1.EnrollingNodeInfo) { i.HostNodeId = &foundationv1.Id{Value: make([]byte, 16)} },
	} {
		info := valid()
		mutate(info)
		_, err := ParseNodeInfo(info)
		refusal, ok := err.(*arc.Refusal)
		if !ok || refusal.Key() != "VALIDATION/invalid_argument" || refusal.Reason != want {
			t.Errorf("%s: %v", want, err)
		}
	}
}
