package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	api "github.com/EdgeCDN-X/edgecdnx-controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testCRDSolver(t *testing.T, zones ...client.Object) (*edgeCDNXProviderSolver, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(zones...).Build()
	return &edgeCDNXProviderSolver{mode: "CRD", kube: kube, ctx: context.Background()}, kube
}

func testZone(namespace, name, domain string) *api.Zone {
	return &api.Zone{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(name + "-uid")},
		Spec:       api.ZoneSpec{Zone: domain, Project: &corev1.LocalObjectReference{Name: "project-a"}},
	}
}

func TestCRDLifecycle(t *testing.T) {
	solver, kube := testCRDSolver(t, testZone("parent", "parent", "example.com"), testZone("tenant", "zone", "sub.example.com"))
	ch := challenge("first")
	ch.ResourceNamespace = "certificates"
	ch.ResolvedFQDN = "_acme-challenge.sub.example.com."
	for _, key := range []string{"first", "first", "second"} {
		ch.Key = key
		if err := solver.Present(ch); err != nil {
			t.Fatal(err)
		}
	}
	record := &api.DNSEndpoint{}
	objectKey := types.NamespacedName{Namespace: "tenant", Name: recordResourceName("_acme-challenge.sub.example.com")}
	if err := kube.Get(context.Background(), objectKey, record); err != nil {
		t.Fatal(err)
	}
	if record.Spec.Project.Name != "project-a" || record.Spec.Zone.Name != "zone" ||
		record.Spec.Zone.Namespace != "tenant" || record.Spec.Zone.UID != "zone-uid" ||
		record.Spec.DNSName != "_acme-challenge.sub.example.com" || record.Spec.RecordType != "TXT" ||
		record.Spec.RoutingPolicy != "Simple" || record.Spec.RecordTTL != 60 ||
		!slices.Equal(record.Spec.Targets, []string{"first", "second"}) {
		t.Fatalf("unexpected record: %+v", record.Spec)
	}
	for _, key := range []string{"absent", "first", "first"} {
		ch.Key = key
		if err := solver.CleanUp(ch); err != nil {
			t.Fatal(err)
		}
	}
	if err := kube.Get(context.Background(), objectKey, record); err != nil || !slices.Equal(record.Spec.Targets, []string{"second"}) {
		t.Fatalf("cleanup lost another value: %+v, %v", record.Spec.Targets, err)
	}
	ch.Key = "second"
	for i := 0; i < 2; i++ {
		if err := solver.CleanUp(ch); err != nil {
			t.Fatal(err)
		}
	}
	if err := kube.Get(context.Background(), objectKey, record); !apierrors.IsNotFound(err) {
		t.Fatalf("expected deleted record, got %v", err)
	}
}

func TestCRDZoneSelection(t *testing.T) {
	solver, _ := testCRDSolver(t, testZone("one", "one", "EXAMPLE.COM."), testZone("two", "two", "example.com"),
		testZone("three", "specific", "sub.example.com"))
	if _, err := solver.findCRDZone(context.Background(), "_acme-challenge.example.com"); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("expected ambiguity error: %v", err)
	}
	zone, err := solver.findCRDZone(context.Background(), "_acme-challenge.sub.example.com")
	if err != nil || zone.Name != "specific" {
		t.Fatalf("expected more specific zone: %+v, %v", zone, err)
	}
	if _, err := solver.findCRDZone(context.Background(), "_acme-challenge.notexample.com"); err == nil {
		t.Fatal("matched outside DNS label boundary")
	}
}

func TestCRDRejectsIncompatibleRecord(t *testing.T) {
	zone := testZone("tenant", "zone", "example.com")
	record := &api.DNSEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: recordResourceName("_acme-challenge.example.com"), Namespace: zone.Namespace},
		Spec: api.DNSEndpointSpec{DNSName: "_acme-challenge.example.com", RecordType: "TXT", RoutingPolicy: "Simple",
			Project: &corev1.LocalObjectReference{Name: "other"}, Zone: &corev1.ObjectReference{Name: zone.Name}, Targets: []string{"existing"}},
	}
	solver, kube := testCRDSolver(t, zone, record)
	if err := solver.CleanUp(challenge("existing")); err == nil {
		t.Fatal("accepted a record from another project")
	}
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(record), record); err != nil || !slices.Equal(record.Spec.Targets, []string{"existing"}) {
		t.Fatalf("incompatible record changed: %v", err)
	}
}

type conflictClient struct {
	client.Client
	conflict bool
}

func (c *conflictClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if !c.conflict {
		c.conflict = true
		record := &api.DNSEndpoint{}
		if err := c.Client.Get(ctx, client.ObjectKeyFromObject(obj), record); err != nil {
			return err
		}
		record.Spec.Targets = append(record.Spec.Targets, "other-writer")
		if err := c.Client.Update(ctx, record); err != nil {
			return err
		}
		return apierrors.NewConflict(schema.GroupResource{Group: api.SchemeGroupVersion.Group, Resource: "dnsendpoints"}, obj.GetName(), errors.New("concurrent update"))
	}
	return c.Client.Update(ctx, obj, opts...)
}

func TestCRDRetryPreservesConcurrentValue(t *testing.T) {
	solver, kube := testCRDSolver(t, testZone("tenant", "zone", "example.com"))
	if err := solver.Present(challenge("first")); err != nil {
		t.Fatal(err)
	}
	solver.kube = &conflictClient{Client: kube}
	if err := solver.Present(challenge("second")); err != nil {
		t.Fatal(err)
	}
	record := &api.DNSEndpoint{}
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: "tenant", Name: recordResourceName("_acme-challenge.example.com")}, record); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(record.Spec.Targets, []string{"first", "other-writer", "second"}) {
		t.Fatalf("concurrent value lost: %v", record.Spec.Targets)
	}
}

type deleteConflictClient struct {
	client.Client
	conflict bool
}

func (c *deleteConflictClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	options := &client.DeleteOptions{}
	for _, opt := range opts {
		opt.ApplyToDelete(options)
	}
	if options.Preconditions == nil || options.Preconditions.UID == nil ||
		*options.Preconditions.UID != obj.GetUID() || options.Preconditions.ResourceVersion == nil ||
		*options.Preconditions.ResourceVersion != obj.GetResourceVersion() {
		return errors.New("delete missing UID or resourceVersion precondition")
	}
	if !c.conflict {
		c.conflict = true
		record := &api.DNSEndpoint{}
		if err := c.Client.Get(ctx, client.ObjectKeyFromObject(obj), record); err != nil {
			return err
		}
		record.Spec.Targets = append(record.Spec.Targets, "other-writer")
		if err := c.Client.Update(ctx, record); err != nil {
			return err
		}
		return apierrors.NewConflict(schema.GroupResource{Group: api.SchemeGroupVersion.Group, Resource: "dnsendpoints"}, obj.GetName(), errors.New("concurrent update"))
	}
	return c.Client.Delete(ctx, obj, opts...)
}

func TestCRDCleanupRetriesConditionalDelete(t *testing.T) {
	solver, kube := testCRDSolver(t, testZone("tenant", "zone", "example.com"))
	if err := solver.Present(challenge("first")); err != nil {
		t.Fatal(err)
	}
	solver.kube = &deleteConflictClient{Client: kube}
	if err := solver.CleanUp(challenge("first")); err != nil {
		t.Fatal(err)
	}
	record := &api.DNSEndpoint{}
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: "tenant", Name: recordResourceName("_acme-challenge.example.com")}, record); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(record.Spec.Targets, []string{"other-writer"}) {
		t.Fatalf("concurrent value lost: %v", record.Spec.Targets)
	}
}

func TestCRDInitialization(t *testing.T) {
	t.Setenv("EDGECDNX_PROJECT_ID", "")
	t.Setenv("EDGECDNX_API_URL", "")
	t.Setenv("EDGECDNX_API_KEY", "")
	solver := &edgeCDNXProviderSolver{mode: "CRD"}
	if err := solver.Initialize(&rest.Config{Host: "https://127.0.0.1"}, nil); err != nil {
		t.Fatalf("CRD mode should not require API settings: %v", err)
	}
	if solver.kube == nil || solver.api != nil {
		t.Fatal("incorrect backend initialized")
	}
	if err := (&edgeCDNXProviderSolver{mode: "CRD"}).Initialize(nil, nil); err == nil {
		t.Fatal("accepted nil Kubernetes config")
	}
	if err := (&edgeCDNXProviderSolver{mode: "unknown"}).Initialize(nil, nil); err == nil {
		t.Fatal("accepted invalid mode")
	}
}
