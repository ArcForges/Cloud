// SPDX-License-Identifier: AGPL-3.0-only

package ingress

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/correlation"
)

const surfaceMethod = "/arcforges.test.v1.Probe/Surface"

func surfaceRig(t *testing.T, options Options) *rig {
	t.Helper()
	r := &rig{t: t}
	registry, err := NewRegistry(
		must(t)(NewUnary(helloMethod, Anonymous, NoScope, 4096, false)),
		must(t)(NewUnary(surfaceMethod, Session, NoScope, 4096, true)).InSurface("identity"),
	)
	if err != nil {
		t.Fatal(err)
	}
	options.Routes = NewRoutes(registry, nil, nil)
	options.Observe = func(_ *http.Request, outcome Outcome) { r.outcomes = append(r.outcomes, outcome) }
	r.pipeline = NewPipeline(options, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		call, _ := CallFrom(request.Context())
		r.calls = append(r.calls, call)
		writer.WriteHeader(http.StatusTeapot)
	}))
	return r
}

// A method of a disabled surface is answered with the domain refusal STATE/not_activated before any credential is read: gRPC
// OK, one reply whose field 3 is the ArcError naming the surface, carrying the correlation of the Worker's traceparent.
func TestADisabledSurfaceIsNotActivatedBeforeAnyCredential(t *testing.T) {
	verified := false
	bearer := fakeBearerFunc(func() (*Caller, error) { verified = true; return &owner, nil })
	for _, enabled := range []func(string) bool{nil, func(string) bool { return false }} {
		r := surfaceRig(t, Options{Bearer: bearer, SurfaceEnabled: enabled})
		recorder := r.do(http.MethodPost, surfaceMethod, metaBody(t, &foundationv1.RequestMeta{}),
			map[string]string{"Authorization": "Bearer abcdefghijklmnop.qrstuvwxyz", "Traceparent": workerTrace})
		body := recorder.Body.Bytes()
		message, ok := ReadSingleMessage(body[:len(body)-len(TrailerFrame(StatusOK, "", false))])
		if recorder.Code != http.StatusOK || !ok || !bytes.HasSuffix(body, TrailerFrame(StatusOK, "", false)) || verified || len(r.calls) != 0 {
			t.Fatalf("reply %d %q verified %v", recorder.Code, body, verified)
		}
		number, wire, length := protowire.ConsumeTag(message)
		if number != 3 || wire != protowire.BytesType {
			t.Fatal("the ArcError is field 3 of the reply")
		}
		value, _ := protowire.ConsumeBytes(message[length:])
		var arcError foundationv1.ArcError
		if err := proto.Unmarshal(value, &arcError); err != nil {
			t.Fatal(err)
		}
		if arcError.GetCode() != "not_activated" || arcError.GetCategory() != foundationv1.ErrorCategory_ERROR_CATEGORY_STATE ||
			arcError.GetMessageKey() != "error.state.not_activated" || arcError.GetDetails().GetState().GetReason() != "identity" ||
			correlation.FormatID(arcError.GetCorrelationId().GetValue()) != "4bf92f35-77b3-4da6-a3ce-929d0e0e4736" {
			t.Fatalf("arc error %v", &arcError)
		}
		if len(r.outcomes) != 1 || r.outcomes[0].Domain != "not_activated" {
			t.Fatalf("outcome %+v", r.outcomes)
		}
	}
}

// A native gRPC caller gets the same reply with the status in HTTP/2 trailers.
func TestTheNotActivatedReplyOfNativeGRPC(t *testing.T) {
	r := surfaceRig(t, Options{})
	request := httptest.NewRequest(http.MethodPost, surfaceMethod, bytes.NewReader(metaBody(t, &foundationv1.RequestMeta{})))
	request.Header.Set("Content-Type", "application/grpc")
	recorder := httptest.NewRecorder()
	r.pipeline.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/grpc" || recorder.Result().Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("native reply %d %v %v", recorder.Code, recorder.Header(), recorder.Result().Trailer)
	}
	if _, ok := ReadSingleMessage(recorder.Body.Bytes()); !ok {
		t.Fatal("one data frame")
	}
}

// An enabled surface admits the call with its client address; hosted mode refuses a surface call whose address is unknown, and the
// Hello needs none.
func TestAnEnabledSurfaceCarriesTheClientAddress(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.7")
	known := func(*http.Request) (netip.Addr, bool) { return address, true }
	unknown := func(*http.Request) (netip.Addr, bool) { return netip.Addr{}, false }
	enabled := func(string) bool { return true }
	auth := map[string]string{"Authorization": "Bearer abcdefghijklmnop.qrstuvwxyz"}
	r := surfaceRig(t, Options{Bearer: fakeBearer{caller: &owner}, SurfaceEnabled: enabled, ClientIP: known, RequireClientIP: true})
	if recorder := r.do(http.MethodPost, surfaceMethod, metaBody(t, &foundationv1.RequestMeta{}), auth); recorder.Code != http.StatusTeapot ||
		len(r.calls) != 1 || r.calls[0].ClientIP != address {
		t.Fatalf("admitted %d %+v", recorder.Code, r.calls)
	}
	r = surfaceRig(t, Options{Bearer: fakeBearer{caller: &owner}, SurfaceEnabled: enabled, ClientIP: unknown, RequireClientIP: true})
	expectRefusal(t, r.do(http.MethodPost, surfaceMethod, metaBody(t, &foundationv1.RequestMeta{}), auth), ReasonInvalidRequest)
	if recorder := r.do(http.MethodPost, helloMethod, Frame(nil), nil); recorder.Code != http.StatusTeapot {
		t.Fatalf("hello refused: %d", recorder.Code)
	}
	r = surfaceRig(t, Options{Bearer: fakeBearer{caller: &owner}, SurfaceEnabled: enabled, ClientIP: unknown})
	if recorder := r.do(http.MethodPost, surfaceMethod, metaBody(t, &foundationv1.RequestMeta{}), auth); recorder.Code != http.StatusTeapot ||
		r.calls[0].ClientIP.IsValid() {
		t.Fatal("a self-hosted center without an address admits the call with an unknown address")
	}
}

// A known bearer whose access token expired or whose credential was revoked gets its own transport refusal.
func TestExpiredAndRevokedBearersAreTheirOwnRefusals(t *testing.T) {
	auth := map[string]string{"Authorization": "Bearer abcdefghijklmnop.qrstuvwxyz"}
	for err, reason := range map[error]Reason{ErrTokenExpired: ReasonTokenExpired, ErrCredentialRevoked: ReasonCredentialRevoked, errors.New("down"): ReasonDependencyUnavailable} {
		r := newRig(t, Options{Bearer: fakeBearer{err: err}})
		expectRefusal(t, r.do(http.MethodPost, accountMethod, metaBody(t, &foundationv1.RequestMeta{}), auth), reason)
		if len(r.calls) != 0 {
			t.Fatal("reached a handler")
		}
	}
}

type fakeBearerFunc func() (*Caller, error)

func (f fakeBearerFunc) Verify(_ context.Context, _ string) (*Caller, error) { return f() }
