package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/miekg/dns"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}
	cmd.RunWebhookServer(GroupName, &edgeCDNXProviderSolver{})
}

type edgeCDNXProviderSolver struct {
	api       *apiClient
	ctx       context.Context
	projectID string
	zones     []apiZone
}

var _ webhook.Solver = (*edgeCDNXProviderSolver)(nil)

func (s *edgeCDNXProviderSolver) Name() string { return "edgecdnx" }

func (s *edgeCDNXProviderSolver) Initialize(_ *rest.Config, stopCh <-chan struct{}) error {
	projectID := os.Getenv("EDGECDNX_PROJECT_ID")
	if !validResourceID(projectID) {
		return errors.New("EDGECDNX_PROJECT_ID must contain a valid Project ID")
	}
	api, err := newAPIClient(os.Getenv("EDGECDNX_API_URL"), os.Getenv("EDGECDNX_API_KEY"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var zones []apiZone
	if err := api.request(ctx, http.MethodGet, "/project/"+url.PathEscape(projectID)+"/zones", nil, &zones); err != nil {
		return fmt.Errorf("fetch Project zones at startup: %w", err)
	}
	if len(zones) == 0 {
		return fmt.Errorf("Project %q has no available zones", projectID)
	}
	seen := make(map[string]bool, len(zones))
	for i := range zones {
		name := normalizeDNSName(zones[i].Spec.Zone)
		if !validResourceID(zones[i].Metadata.Name) || len(validation.IsDNS1123Subdomain(name)) != 0 {
			return errors.New("API returned an invalid zone name or ID")
		}
		if seen[name] {
			return fmt.Errorf("API returned duplicate DNS zone %q", name)
		}
		seen[name] = true
		zones[i].Spec.Zone = name
	}
	s.api, s.projectID, s.zones = api, projectID, zones
	s.ctx = context.Background()
	if stopCh != nil {
		ctx, cancel := context.WithCancel(s.ctx)
		s.ctx = ctx
		go func() {
			<-stopCh
			cancel()
			api.http.CloseIdleConnections()
		}()
	}
	return nil
}

func (s *edgeCDNXProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	return s.change(ch, true)
}

func (s *edgeCDNXProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	return s.change(ch, false)
}

func validResourceID(id string) bool {
	return id != "" && id != "." && id != ".." && !strings.ContainsAny(id, "/\\?# \t\r\n")
}

func normalizeDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func (s *edgeCDNXProviderSolver) change(ch *v1alpha1.ChallengeRequest, present bool) error {
	if s.api == nil || s.ctx == nil {
		return errors.New("EdgeCDN-X solver is not initialized")
	}
	if ch == nil || ch.Key == "" {
		return errors.New("challenge and TXT value are required")
	}
	if ch.Config != nil && len(ch.Config.Raw) != 0 {
		var config map[string]json.RawMessage
		if err := json.Unmarshal(ch.Config.Raw, &config); err != nil {
			return fmt.Errorf("decode Issuer config: %w", err)
		}
		if len(config) != 0 {
			return errors.New("per-Issuer config is not supported; configure EDGECDNX_PROJECT_ID on the deployment")
		}
	}
	name := normalizeDNSName(ch.ResolvedFQDN)
	if _, ok := dns.IsDomainName(name); !ok || name == "" {
		return errors.New("challenge must have a valid resolved DNS name")
	}
	zone, err := s.matchZone(name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	path := "/project/" + url.PathEscape(s.projectID) + "/zones/" + url.PathEscape(zone.Metadata.Name) + "/dns-endpoints"
	recordPath := path + "/" + recordResourceName(name)
	for attempt := 0; attempt < 6; attempt++ {
		err = s.changeRecord(ctx, path, recordPath, name, ch.Key, 60, present)
		if !hasStatus(err, http.StatusConflict) && !hasStatus(err, http.StatusNotFound) {
			return err
		}

		if attempt < 5 {
			timer := time.NewTimer(time.Duration(1<<attempt) * 50 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return fmt.Errorf("DNS endpoint changed during all retry attempts: %w", err)
}

func (s *edgeCDNXProviderSolver) matchZone(name string) (apiZone, error) {
	name = normalizeDNSName(name)
	var best apiZone
	for _, zone := range s.zones {
		if (name == zone.Spec.Zone || strings.HasSuffix(name, "."+zone.Spec.Zone)) && len(zone.Spec.Zone) > len(best.Spec.Zone) {
			best = zone
		}
	}
	if best.Metadata.Name == "" {
		return best, fmt.Errorf("no available zone covers %q in Project %q", name, s.projectID)
	}
	return best, nil
}

// Match the API's DNS endpoint naming, including delegated names without underscores.
func recordResourceName(name string) string {
	resourceName := name + "-txt"
	if len(validation.IsDNS1123Subdomain(resourceName)) == 0 {
		return resourceName
	}
	digest := sha256.Sum256([]byte(resourceName))
	return fmt.Sprintf("dnsendpoint-%x", digest[:12])
}

func (s *edgeCDNXProviderSolver) changeRecord(ctx context.Context, path, recordPath, name, key string, ttl int, present bool) error {
	var record apiRecord
	err := s.api.request(ctx, http.MethodGet, recordPath, nil, &record)
	if hasStatus(err, http.StatusNotFound) {
		if !present {
			return nil
		}
		return s.api.request(ctx, http.MethodPost, path, recordSpec{
			DNSName: name, RecordType: "TXT", RecordTTL: ttl, RoutingPolicy: "Simple", Targets: []string{key},
		}, nil)
	}
	if err != nil {
		return err
	}
	if record.Metadata.ResourceVersion == "" || normalizeDNSName(record.Spec.DNSName) != name ||
		record.Spec.RecordType != "TXT" || record.Spec.RoutingPolicy != "Simple" {
		return errors.New("API returned an incompatible DNS endpoint or missing resourceVersion")
	}
	targets := make([]string, 0, len(record.Spec.Targets)+1)
	found := false
	for _, target := range record.Spec.Targets {
		if target == key {
			found = true
			if !present {
				continue
			}
		}
		targets = append(targets, target)
	}
	if found == present {
		return nil
	}
	if present {
		targets = append(targets, key)
	}
	if len(targets) == 0 {
		return s.api.request(ctx, http.MethodDelete, recordPath+"?resourceVersion="+url.QueryEscape(record.Metadata.ResourceVersion), nil, nil)
	}
	return s.api.request(ctx, http.MethodPatch, recordPath, struct {
		ResourceVersion string   `json:"resourceVersion"`
		Targets         []string `json:"targets"`
	}{record.Metadata.ResourceVersion, targets}, nil)
}
