package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	infrastructurev1alpha1 "github.com/EdgeCDN-X/edgecdnx-controller/api/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/miekg/dns"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type testAPI struct {
	sync.Mutex
	record         *infrastructurev1alpha1.DNSEndpoint
	version        int
	conflict       bool
	zoneReads      int
	zoneBody       string
	zoneStatus     int
	recordRequests int
}

func (a *testAPI) serve(w http.ResponseWriter, r *http.Request) {
	a.Lock()
	defer a.Unlock()
	if r.Header.Get("Authorization") != "ApiKey test-key" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	base := "/project/project-a/zones"
	if r.URL.Path == base && r.Method == http.MethodGet {
		a.zoneReads++
		if a.zoneStatus != 0 {
			w.WriteHeader(a.zoneStatus)
		}
		if a.zoneBody != "" {
			fmt.Fprint(w, a.zoneBody)
			return
		}
		fmt.Fprint(w, `[{"metadata":{"name":"zone-id"},"spec":{"zone":"example.com"}}]`)
		return
	}
	collection := base + "/zone-id/dns-endpoints"
	a.recordRequests++
	if r.URL.Path != collection && !strings.HasPrefix(r.URL.Path, collection+"/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method == http.MethodGet {
		if a.record == nil {
			w.WriteHeader(http.StatusNotFound)
		} else {
			_ = json.NewEncoder(w).Encode(a.record)
		}
		return
	}
	if r.Method == http.MethodPost {
		if a.record != nil {
			w.WriteHeader(http.StatusConflict)
			return
		}
		a.record = &infrastructurev1alpha1.DNSEndpoint{}
		if err := json.NewDecoder(r.Body).Decode(&a.record.Spec); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		a.version++
		a.record.ResourceVersion = strconv.Itoa(a.version)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(a.record)
		return
	}
	if a.record == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var patch struct {
		ResourceVersion string   `json:"resourceVersion"`
		Targets         []string `json:"targets"`
	}
	if r.Method == http.MethodPatch {
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	} else {
		patch.ResourceVersion = r.URL.Query().Get("resourceVersion")
	}
	if a.conflict {
		a.conflict = false
		a.version++
		a.record.ResourceVersion = strconv.Itoa(a.version)
		a.record.Spec.Targets = append(a.record.Spec.Targets, "other-writer")
	}
	if patch.ResourceVersion != a.record.ResourceVersion {
		w.WriteHeader(http.StatusConflict)
		return
	}
	switch r.Method {
	case http.MethodPatch:
		a.record.Spec.Targets = patch.Targets
		a.version++
		a.record.ResourceVersion = strconv.Itoa(a.version)
		_ = json.NewEncoder(w).Encode(a.record)
		return
	case http.MethodDelete:
		a.record = nil
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func testSolver(t *testing.T) (*edgeCDNXProviderSolver, *testAPI) {
	t.Helper()
	state := &testAPI{}
	server := httptest.NewServer(http.HandlerFunc(state.serve))
	t.Cleanup(server.Close)
	t.Setenv("EDGECDNX_API_URL", server.URL)
	t.Setenv("EDGECDNX_API_KEY", "test-key")
	t.Setenv("EDGECDNX_PROJECT_ID", "project-a")
	solver := &edgeCDNXProviderSolver{}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	if err := solver.Initialize(nil, stop); err != nil {
		t.Fatal(err)
	}
	return solver, state
}

func challenge(key string) *v1alpha1.ChallengeRequest {
	return &v1alpha1.ChallengeRequest{
		ResolvedFQDN: "_acme-challenge.example.com.", ResolvedZone: "example.com.", Key: key,
	}
}

func TestSolverLifecycle(t *testing.T) {
	solver, state := testSolver(t)
	for _, key := range []string{"first", "first", "second"} {
		if err := solver.Present(challenge(key)); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(state.record.Spec.Targets, []string{"first", "second"}) || state.record.Spec.RecordTTL != 60 {
		t.Fatalf("unexpected record: %+v", state.record)
	}
	for _, key := range []string{"absent", "first", "first"} {
		if err := solver.CleanUp(challenge(key)); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(state.record.Spec.Targets, []string{"second"}) {
		t.Fatalf("cleanup removed unrelated values: %+v", state.record)
	}
	for i := 0; i < 2; i++ {
		if err := solver.CleanUp(challenge("second")); err != nil {
			t.Fatal(err)
		}
	}
	if state.record != nil {
		t.Fatal("last TXT value was not deleted")
	}
	if state.zoneReads != 8 {
		t.Fatalf("zones fetched %d times; expected once for each of 8 requests", state.zoneReads)
	}
}

func TestSolverRefreshesZonesOnEachRequest(t *testing.T) {
	solver, state := testSolver(t)
	if state.zoneReads != 0 {
		t.Fatal("Initialize fetched zones")
	}
	ch := challenge("refresh")
	ch.ResolvedFQDN = "_acme-challenge.new.example.net."
	if err := solver.Present(ch); err == nil {
		t.Fatal("accepted challenge before its zone was added")
	}
	state.zoneBody = `[{"metadata":{"name":"zone-id"},"spec":{"zone":"example.net"}}]`
	if err := solver.Present(ch); err != nil {
		t.Fatalf("did not discover newly added zone: %v", err)
	}
	requests := state.recordRequests
	state.zoneBody = `[]`
	if err := solver.CleanUp(ch); err == nil {
		t.Fatal("cleanup used stale zone after removal")
	}
	state.zoneBody = `{"error":"unavailable"}`
	state.zoneStatus = http.StatusServiceUnavailable
	if err := solver.Present(ch); !hasStatus(err, http.StatusServiceUnavailable) {
		t.Fatalf("discovery failure not surfaced: %v", err)
	}
	if state.recordRequests != requests {
		t.Fatal("accessed records despite failed discovery")
	}
	state.zoneStatus = 0
	state.zoneBody = `[{"metadata":{"name":"zone-id"},"spec":{"zone":"example.net"}}]`
	if err := solver.CleanUp(ch); err != nil {
		t.Fatalf("cleanup did not recover after restoring zone: %v", err)
	}
	if state.record != nil || state.zoneReads != 5 {
		t.Fatalf("unexpected refresh lifecycle: record=%+v, zone reads=%d", state.record, state.zoneReads)
	}
}

func TestSolverConcurrentChallenges(t *testing.T) {
	solver, state := testSolver(t)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := solver.Present(challenge(fmt.Sprint(i))); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if state.record == nil || len(state.record.Spec.Targets) != 5 {
		t.Fatalf("lost concurrent challenge: %+v", state.record)
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := solver.CleanUp(challenge(fmt.Sprint(i))); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if state.record != nil {
		t.Fatalf("concurrent cleanup left record: %+v", state.record)
	}
}

func TestSolverConflictPreservesOtherWriter(t *testing.T) {
	solver, state := testSolver(t)
	if err := solver.Present(challenge("first")); err != nil {
		t.Fatal(err)
	}
	state.conflict = true
	if err := solver.CleanUp(challenge("first")); err != nil {
		t.Fatal(err)
	}
	if state.record == nil || !slices.Equal(state.record.Spec.Targets, []string{"other-writer"}) {
		t.Fatalf("conflict lost another writer: %+v", state.record)
	}
}

func TestSolverValidation(t *testing.T) {
	solver, _ := testSolver(t)
	for _, raw := range []string{`{`, `{"projectID":"a"}`, `{"recordTTL":60}`, `{"zoneID":"a"}`} {
		ch := challenge("test")
		ch.Config = &extapi.JSON{Raw: []byte(raw)}
		if err := solver.Present(ch); err == nil {
			t.Errorf("accepted unsupported config %s", raw)
		}
	}
	ch := challenge("test")
	ch.ResolvedFQDN = "_acme-challenge.other.com."
	if err := solver.Present(ch); err == nil {
		t.Fatal("accepted name outside available zones")
	}
	if err := solver.Present(nil); err == nil {
		t.Fatal("accepted nil challenge")
	}
}

func TestZoneMatching(t *testing.T) {
	solver, _ := testSolver(t)
	var zones []infrastructurev1alpha1.Zone
	if err := json.Unmarshal([]byte(`[
		{"metadata":{"name":"parent"},"spec":{"zone":"example.com"}},
		{"metadata":{"name":"child"},"spec":{"zone":"sub.example.com"}},
		{"metadata":{"name":"other"},"spec":{"zone":"example.net"}}
	]`), &zones); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, id string }{
		{"_acme-challenge.example.com.", "parent"},
		{"_acme-challenge.SUB.EXAMPLE.COM.", "child"},
		{"sub.example.com", "child"},
		{"validation.example.net", "other"},
	} {
		zone, err := matchZone(zones, test.name, solver.projectID)
		if err != nil || zone.Name != test.id {
			t.Fatalf("match %s: got %s, %v", test.name, zone.Name, err)
		}
	}
	for _, name := range []string{"badexample.com", "example.com.attacker.net"} {
		if _, err := matchZone(zones, name, solver.projectID); err == nil {
			t.Fatalf("accepted unrelated name %s", name)
		}
	}
}

func TestRequestZoneDiscovery(t *testing.T) {
	t.Setenv("EDGECDNX_PROJECT_ID", "project-a")
	t.Setenv("EDGECDNX_API_KEY", "test-key")
	for _, test := range []struct {
		name, body string
		status     int
		success    bool
	}{
		{"valid", `[{"metadata":{"name":"zone-id"},"spec":{"zone":"Example.COM."}}]`, 200, true},
		{"empty", `[]`, 200, false},
		{"malformed", `{`, 200, false},
		{"forbidden", `{}`, 403, false},
		{"invalid zone", `[{"metadata":{"name":"zone-id"},"spec":{"zone":"bad zone"}}]`, 200, false},
		{"invalid id", `[{"metadata":{"name":"../bad"},"spec":{"zone":"example.com"}}]`, 200, false},
		{"duplicate", `[{"metadata":{"name":"a"},"spec":{"zone":"example.com"}},{"metadata":{"name":"b"},"spec":{"zone":"EXAMPLE.COM."}}]`, 200, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/project/project-a/zones" || r.Header.Get("Authorization") != "ApiKey test-key" {
					t.Errorf("unexpected discovery request: %s", r.URL.Path)
				}
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			t.Setenv("EDGECDNX_API_URL", server.URL)
			solver := &edgeCDNXProviderSolver{}
			err := solver.Initialize(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			zones, err := solver.fetchZones(context.Background())
			if (err == nil) != test.success {
				t.Fatalf("fetchZones returned %v, success expected %v", err, test.success)
			}
			if test.success && zones[0].Spec.Zone != "example.com" {
				t.Fatal("zone was not normalized")
			}
		})
	}
	t.Setenv("EDGECDNX_PROJECT_ID", "")
	if err := (&edgeCDNXProviderSolver{}).Initialize(nil, nil); err == nil {
		t.Fatal("accepted missing Project ID")
	}
}

func TestSolverDelegatedChallenge(t *testing.T) {
	solver, state := testSolver(t)
	ch := challenge("delegated")
	ch.ResolvedFQDN = "validation.example.com."
	if err := solver.Present(ch); err != nil {
		t.Fatal(err)
	}
	if state.record.Spec.DNSName != "validation.example.com" || recordResourceName(state.record.Spec.DNSName) != "validation.example.com-txt" {
		t.Fatalf("incorrect delegated record: %+v", state.record)
	}
	if err := solver.CleanUp(ch); err != nil {
		t.Fatal(err)
	}
}

func TestRecordNamingAndTXTWireValue(t *testing.T) {
	if got := recordResourceName("_acme-challenge.example.com"); got != "dnsendpoint-043e25b653e31517a931b4c3" {
		t.Fatalf("record name differs from the API contract: %s", got)
	}
	key := "uB-q9pQ_1234567890"
	record, err := dns.NewRR("_acme-challenge.example.com. 60 IN TXT " + key)
	if err != nil {
		t.Fatal(err)
	}
	txt, ok := record.(*dns.TXT)
	if !ok || len(txt.Txt) != 1 || txt.Txt[0] != key {
		t.Fatalf("TXT wire value differs from challenge key: %v", record)
	}
}

func TestAPIErrorsAndRedirects(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError, http.StatusFound} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/redirect")
				w.WriteHeader(status)
				fmt.Fprint(w, "secret-key")
			}))
			defer server.Close()
			client, err := newAPIClient(server.URL, "secret-key")
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Zones.List(context.Background(), "project-a")
			err = client.safeError(err)
			if !hasStatus(err, status) || strings.Contains(err.Error(), "secret-key") {
				t.Fatalf("unexpected API error: %v", err)
			}
		})
	}
	for _, base := range []string{"", "/relative", "ftp://example.com", "http://user:pass@example.com", "https://example.com?key=x"} {
		if _, err := newAPIClient(base, "key"); err == nil {
			t.Errorf("accepted invalid API URL %q", base)
		}
	}
	if _, err := newAPIClient("https://example.com", ""); err == nil {
		t.Fatal("accepted missing API key")
	}
}

func TestSDKErrorBodiesAreNotReturned(t *testing.T) {
	for _, body := range []string{
		`{"error":"server echoed secret-key and private response data"}`,
		"server echoed secret-key and private response data",
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, body)
		}))
		client, err := newAPIClient(server.URL, "secret-key")
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		solver := &edgeCDNXProviderSolver{api: client, projectID: "project-a", ctx: context.Background()}
		err = solver.Present(challenge("value"))
		server.Close()
		if !hasStatus(err, http.StatusForbidden) || strings.Contains(err.Error(), "secret-key") ||
			strings.Contains(err.Error(), "private response data") {
			t.Fatalf("unexpected returned error: %v", err)
		}
	}
}

func TestSDKResponseSizeLimit(t *testing.T) {
	solver, state := testSolver(t)
	state.zoneBody = strings.Repeat(" ", 1<<20) + `[]`
	if _, err := solver.fetchZones(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeds 1 MiB") {
		t.Fatalf("oversized SDK response was not rejected: %v", err)
	}
}

func TestSDKContextCancellation(t *testing.T) {
	solver, state := testSolver(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	solver.ctx = ctx
	if err := solver.Present(challenge("value")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if state.zoneReads != 0 || state.recordRequests != 0 {
		t.Fatal("canceled challenge accessed API")
	}
}

func TestSolverRejectsIncompatibleSDKRecord(t *testing.T) {
	for _, test := range []struct {
		name, version, dnsName, recordType, policy string
	}{
		{"missing version", "", "_acme-challenge.example.com", "TXT", "Simple"},
		{"wrong name", "1", "other.example.com", "TXT", "Simple"},
		{"wrong type", "1", "_acme-challenge.example.com", "A", "Simple"},
		{"wrong policy", "1", "_acme-challenge.example.com", "TXT", "Failover"},
	} {
		t.Run(test.name, func(t *testing.T) {
			solver, state := testSolver(t)
			state.record = &infrastructurev1alpha1.DNSEndpoint{
				ObjectMeta: metav1.ObjectMeta{ResourceVersion: test.version},
				Spec: infrastructurev1alpha1.DNSEndpointSpec{
					DNSName: test.dnsName, RecordType: test.recordType, RoutingPolicy: test.policy,
					Targets: []string{"existing"},
				},
			}
			if err := solver.Present(challenge("new")); err == nil {
				t.Fatal("accepted incompatible record")
			}
			if !slices.Equal(state.record.Spec.Targets, []string{"existing"}) || state.recordRequests != 1 {
				t.Fatal("modified incompatible record")
			}
		})
	}
}

// Opt-in: creates real TXT records and removes only the test's values.
func TestLiveAPI(t *testing.T) {
	if os.Getenv("EDGECDNX_LIVE_TEST") != "1" {
		t.Skip("set EDGECDNX_LIVE_TEST=1 and the documented API/zone environment")
	}
	solver := &edgeCDNXProviderSolver{}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	if err := solver.Initialize(nil, stop); err != nil {
		t.Fatal(err)
	}
	zone, err := liveTestZone(solver, os.Getenv("EDGECDNX_TEST_ZONE"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("testing Project %s, zone %s", solver.projectID, zone)
	ch := &v1alpha1.ChallengeRequest{
		ResolvedFQDN: "_acme-challenge.webhook-test." + strings.TrimSuffix(zone, ".") + ".",
		ResolvedZone: zone, Key: fmt.Sprintf("edgecdnx-webhook-test-%d", os.Getpid()),
	}
	t.Cleanup(func() {
		if err := solver.CleanUp(ch); err != nil {
			t.Errorf("live cleanup failed: %v", err)
		}
	})
	for i := 0; i < 2; i++ {
		if err := solver.Present(ch); err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < 2; i++ {
		if err := solver.CleanUp(ch); err != nil {
			t.Fatal(err)
		}
	}
}

func liveTestZone(solver *edgeCDNXProviderSolver, requested string) (string, error) {
	ctx, cancel := context.WithTimeout(solver.ctx, 30*time.Second)
	defer cancel()
	zones, err := solver.fetchZones(ctx)
	if err != nil {
		return "", err
	}
	if requested != "" {
		zone, err := matchZone(zones, requested, solver.projectID)
		if err != nil {
			return "", err
		}
		if zone.Spec.Zone != normalizeDNSName(requested) {
			return "", fmt.Errorf("test zone %q is not an available API zone", requested)
		}
		return zone.Spec.Zone, nil
	}
	names := make([]string, 0, len(zones))
	for _, zone := range zones {
		names = append(names, zone.Spec.Zone)
	}
	if len(names) == 0 {
		return "", fmt.Errorf("no available zones for live testing")
	}
	slices.Sort(names)
	return names[0], nil
}

func TestLiveTestZoneSelection(t *testing.T) {
	solver, _ := testSolver(t)
	for _, requested := range []string{"", "EXAMPLE.COM."} {
		zone, err := liveTestZone(solver, requested)
		if err != nil || zone != "example.com" {
			t.Fatalf("select %q: got %q, %v", requested, zone, err)
		}
	}
	for _, requested := range []string{"other.com", "sub.example.com"} {
		if _, err := liveTestZone(solver, requested); err == nil {
			t.Fatalf("accepted unavailable test zone %q", requested)
		}
	}
}
