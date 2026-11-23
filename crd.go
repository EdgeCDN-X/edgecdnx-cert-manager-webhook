package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	infrastructurev1alpha1 "github.com/EdgeCDN-X/edgecdnx-controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func newCRDClient(config *rest.Config) (client.Client, error) {
	scheme := runtime.NewScheme()
	if err := infrastructurev1alpha1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	return client.New(config, client.Options{Scheme: scheme})
}

func (s *edgeCDNXProviderSolver) findCRDZone(ctx context.Context, name string) (infrastructurev1alpha1.Zone, error) {
	var zones infrastructurev1alpha1.ZoneList
	if err := s.kube.List(ctx, &zones); err != nil {
		return infrastructurev1alpha1.Zone{}, fmt.Errorf("list Zones: %w", err)
	}
	var best infrastructurev1alpha1.Zone
	ambiguous := false
	for _, zone := range zones.Items {
		domain := normalizeDNSName(zone.Spec.Zone)
		if len(validation.IsDNS1123Subdomain(domain)) != 0 ||
			(name != domain && !strings.HasSuffix(name, "."+domain)) {
			continue
		}
		if len(domain) > len(best.Spec.Zone) {
			zone.Spec.Zone = domain
			best = zone
			ambiguous = false
		} else if len(domain) == len(best.Spec.Zone) {
			ambiguous = true
		}
	}
	if best.Name == "" {
		return best, fmt.Errorf("no Zone covers %q", name)
	}
	if ambiguous {
		return best, fmt.Errorf("multiple Zones cover %q with the same most-specific domain %q", name, best.Spec.Zone)
	}
	if best.Spec.Project == nil || best.Spec.Project.Name == "" || !best.DeletionTimestamp.IsZero() {
		return best, fmt.Errorf("Zone %s/%s has no Project or is being deleted", best.Namespace, best.Name)
	}
	return best, nil
}

func (s *edgeCDNXProviderSolver) changeCRD(ctx context.Context, name, key string, present bool) error {
	zone, err := s.findCRDZone(ctx, name)
	if err != nil {
		return err
	}
	action := "CleanUp"
	if present {
		action = "Present"
	}
	klog.V(4).InfoS("EdgeCDN-X solver matched zone", "action", action, "fqdn", name,
		"namespace", zone.Namespace, "zoneID", zone.Name, "zone", zone.Spec.Zone,
		"recordID", recordResourceName(name))
	for attempt := 0; attempt < 6; attempt++ {
		err = s.changeCRDRecord(ctx, zone, name, key, present)
		if !apierrors.IsConflict(err) && !apierrors.IsAlreadyExists(err) && !apierrors.IsNotFound(err) {
			if err == nil {
				klog.V(4).InfoS("EdgeCDN-X solver completed challenge", "action", action, "fqdn", name)
			}
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

func (s *edgeCDNXProviderSolver) changeCRDRecord(ctx context.Context, zone infrastructurev1alpha1.Zone, name, key string, present bool) error {
	record := &infrastructurev1alpha1.DNSEndpoint{}
	objectKey := types.NamespacedName{Namespace: zone.Namespace, Name: recordResourceName(name)}
	err := s.kube.Get(ctx, objectKey, record)
	if apierrors.IsNotFound(err) {
		if !present {
			return nil
		}
		record = &infrastructurev1alpha1.DNSEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: objectKey.Name, Namespace: objectKey.Namespace},
			Spec: infrastructurev1alpha1.DNSEndpointSpec{
				Project:       &corev1.LocalObjectReference{Name: zone.Spec.Project.Name},
				Zone:          &corev1.ObjectReference{Name: zone.Name, Namespace: zone.Namespace, UID: zone.UID},
				DNSName:       name,
				RecordType:    "TXT",
				RecordTTL:     60,
				RoutingPolicy: "Simple",
				Targets:       []string{key},
			},
		}
		return s.kube.Create(ctx, record)
	}
	if err != nil {
		return fmt.Errorf("get DNSEndpoint %s: %w", objectKey, err)
	}
	ref := record.Spec.Zone
	if record.ResourceVersion == "" || normalizeDNSName(record.Spec.DNSName) != name ||
		record.Spec.RecordType != "TXT" || record.Spec.RoutingPolicy != "Simple" ||
		record.Spec.Project == nil || record.Spec.Project.Name != zone.Spec.Project.Name ||
		ref == nil || ref.Name != zone.Name || (ref.Namespace != "" && ref.Namespace != zone.Namespace) ||
		(ref.UID != "" && ref.UID != zone.UID) {
		return errors.New("incompatible DNSEndpoint or missing resourceVersion")
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
		return s.kube.Delete(ctx, record, &client.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &record.UID, ResourceVersion: &record.ResourceVersion},
		})
	}
	record.Spec.Targets = targets
	return s.kube.Update(ctx, record)
}
