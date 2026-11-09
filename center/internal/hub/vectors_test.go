// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/proto"
)

// The Contracts golden vectors of the node channel and the error catalogue, vendored byte for byte at the published cohort
// (center/internal/hub/testdata; EVIDENCE: REAL vectors of Contracts e67a6b0, the bytes and signatures the C# and Go bindings of the
// cohort check). The SHA-256 of each vendored file is pinned, so an edit that keeps the counts but flips a byte fails here.
const (
	vectorsCohort       = "1.0.0-ci.437.1"
	vectorsCommit       = "e67a6b089a7270ab771a97c27aeba92c5d3b0469"
	vectorsFile         = "testdata/af-ctr-05-relay-vectors.json"
	vectorsSHA256       = "8b6f1fb333a6aad96c32467b77148894ed0fce04d54fc9603c7b8c620fdec899"
	catalogueFile       = "testdata/af-ctr-06-error-catalogue-450.json"
	catalogueFileSHA256 = "7069a1a94eb99c6fb40fea16c17e1f2942510cdc8762ec2cc83622c1e543d412"
	catalogueCohort     = "1.0.0-ci.450.1"
)

type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	value, err := hex.DecodeString(text)
	*h = value
	return err
}

type vectorAssertion struct {
	ID                               string    `json:"id"`
	Assertion                        hexBytes  `json:"assertion"`
	SigningInput                     hexBytes  `json:"signingInput"`
	Signature                        hexBytes  `json:"signature"`
	HighS                            hexBytes  `json:"highSSignature"`
	RequestSHA256                    hexBytes  `json:"requestSha256"`
	ListNodesRequest                 *hexBytes `json:"listNodesRequest"`
	ListNodesRequestWithoutAssertion *hexBytes `json:"listNodesRequestWithoutAssertion"`
	GetNodeRequest                   *hexBytes `json:"getNodeRequest"`
	GetNodeRequestWithoutAssertion   *hexBytes `json:"getNodeRequestWithoutAssertion"`
}

type relayVectors struct {
	Audience       string            `json:"audience"`
	AudienceSHA256 hexBytes          `json:"audienceSha256"`
	Domains        map[string]string `json:"domains"`
	Keys           map[string]struct {
		KID  string   `json:"kid"`
		SPKI hexBytes `json:"spki"`
	} `json:"keys"`
	IDs        map[string]string `json:"ids"`
	RoutedCall struct {
		Frame                hexBytes                          `json:"frame"`
		FrameSeq             uint64                            `json:"frameSeq"`
		CallHeader           hexBytes                          `json:"callHeader"`
		Signature            hexBytes                          `json:"signature"`
		SigningInput         hexBytes                          `json:"signingInput"`
		Payload              hexBytes                          `json:"payload"`
		PayloadSHA256        hexBytes                          `json:"payloadSha256"`
		KID                  string                            `json:"kid"`
		IssuedAt             [2]int64                          `json:"issuedAt"`
		ExpiresAt            [2]int64                          `json:"expiresAt"`
		Deadline             [2]int64                          `json:"deadline"`
		Method               int32                             `json:"method"`
		RequestSize          uint32                            `json:"requestSize"`
		RelayAssertionSHA256 hexBytes                          `json:"relayAssertionSha256"`
		HighS                hexBytes                          `json:"highSSignature"`
		Caller               struct{ Kind, LocalOrigin int32 } `json:"caller"`
	} `json:"routedCall"`
	RoutedResult struct {
		Frame         hexBytes `json:"frame"`
		ResultHeader  hexBytes `json:"resultHeader"`
		Signature     hexBytes `json:"signature"`
		SigningInput  hexBytes `json:"signingInput"`
		Payload       hexBytes `json:"payload"`
		PayloadSHA256 hexBytes `json:"payloadSha256"`
		HighS         hexBytes `json:"highSSignature"`
	} `json:"routedResult"`
	RelayAssertions []vectorAssertion `json:"relayAssertions"`
	RelayNonce      struct {
		RequestFrame hexBytes `json:"requestFrame"`
		Frame        hexBytes `json:"frame"`
		Nonce        hexBytes `json:"nonce"`
	} `json:"relayNonce"`
}

// loadVectors reads the vendored vectors and checks the pinned digest.
func loadVectors(t *testing.T) relayVectors {
	t.Helper()
	data, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	if digest := sha256.Sum256(data); hex.EncodeToString(digest[:]) != vectorsSHA256 {
		t.Fatalf("%s is not the vendored Contracts %s (%s) file", vectorsFile, vectorsCohort, vectorsCommit)
	}
	var vectors relayVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func mustID(t *testing.T, text string) *foundationv1.Id {
	t.Helper()
	value, err := hex.DecodeString(text)
	if err != nil || len(value) != 16 {
		t.Fatalf("an ID of the vectors: %q", text)
	}
	return &foundationv1.Id{Value: value}
}

func vectorInstant(pair [2]int64) *foundationv1.Instant {
	return &foundationv1.Instant{UnixSeconds: proto.Int64(pair[0]), Nanos: proto.Uint32(uint32(pair[1]))}
}

// clone copies a message so a case changes only its own copy.
func clone[T proto.Message](value T) T { return proto.Clone(value).(T) }

func TestTheVendoredFilesAreTheCohorts(t *testing.T) {
	vectors := loadVectors(t)
	if digest := sha256.Sum256([]byte(vectors.Audience)); !bytes.Equal(digest[:], vectors.AudienceSHA256) {
		t.Fatal("the audience digest")
	}
	data, err := os.ReadFile(catalogueFile)
	if err != nil {
		t.Fatal(err)
	}
	if digest := sha256.Sum256(data); hex.EncodeToString(digest[:]) != catalogueFileSHA256 {
		t.Fatalf("%s is not the vendored Contracts %s file", catalogueFile, catalogueCohort)
	}
}

// Historical source evidence is retained rather than rewritten to match a later cohort.
func TestCTR06HistoricalRefusalCatalogueRemainsByteExact(t *testing.T) {
	data, err := os.ReadFile("testdata/af-con-01-error-catalogue.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != "2a5737b21ef8be586ece156d2c4780208d93eb9ea42b2885fbd3d2b5f97efa64" {
		t.Fatal("historical catalogue changed")
	}
	var old struct {
		Codes []struct{ Category, Code string }
	}
	if err := json.Unmarshal(data, &old); err != nil {
		t.Fatal(err)
	}
	if len(old.Codes) != 67 || len(refusalCatalogue) != 70 {
		t.Fatal("unexpected old/new catalogue closure")
	}
	for _, code := range old.Codes {
		if !catalogued(strings.ToLower(code.Category) + "/" + code.Code) {
			t.Fatal("historical refusal disappeared")
		}
	}
	for _, key := range []string{"conflict/file_changed", "conflict/occurrence_mismatch", "state/file_access_denied"} {
		if !catalogued(key) {
			t.Fatal("missing published450 code", key)
		}
	}
}
