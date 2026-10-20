/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package podcertssigner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

func TestSelectorMatchesLabels(t *testing.T) {
	notMatched := &SigningErrorEvent{
		Reason:  serviceLabelsNotMatchedReason,
		Message: `pod does not match "my-svc" service's selector`,
	}

	tests := []struct {
		name        string
		selector    map[string]string
		podLabels   map[string]string
		expectedEvt *SigningErrorEvent
	}{
		{
			name:      "selector matches pod labels exactly",
			selector:  map[string]string{"app": "foo"},
			podLabels: map[string]string{"app": "foo"},
		},
		{
			name:      "selector is a subset of pod labels",
			selector:  map[string]string{"app": "foo"},
			podLabels: map[string]string{"app": "foo", "tier": "backend"},
		},
		{
			name:      "multi-key selector fully matches",
			selector:  map[string]string{"app": "foo", "tier": "backend"},
			podLabels: map[string]string{"app": "foo", "tier": "backend", "extra": "x"},
		},
		{
			name:        "label value differs",
			selector:    map[string]string{"app": "foo"},
			podLabels:   map[string]string{"app": "bar"},
			expectedEvt: notMatched,
		},
		{
			name:        "selector key missing from pod",
			selector:    map[string]string{"app": "foo"},
			podLabels:   map[string]string{"tier": "backend"},
			expectedEvt: notMatched,
		},
		{
			name:        "only part of a multi-key selector matches",
			selector:    map[string]string{"app": "foo", "tier": "backend"},
			podLabels:   map[string]string{"app": "foo"},
			expectedEvt: notMatched,
		},
		{
			name:        "pod without labels",
			selector:    map[string]string{"app": "foo"},
			podLabels:   nil,
			expectedEvt: notMatched,
		},
		{
			// A selector-less service has no endpoints from selection, so no pod is allowed to claim it.
			name:        "nil selector never matches",
			selector:    nil,
			podLabels:   map[string]string{"app": "foo"},
			expectedEvt: notMatched,
		},
		{
			name:        "empty selector never matches",
			selector:    map[string]string{},
			podLabels:   nil,
			expectedEvt: notMatched,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := &corev1.Service{
				Name: "my-svc", Namespace: "ns",
				Spec: corev1.ServiceSpec{Selector: tc.selector},
			}
			pod := &corev1.Pod{
				Name: "my-pod", Namespace: "ns", Labels: tc.podLabels,
			}

			got := selectorMatchesLabels(svc, pod)
			if diff := cmp.Diff(tc.expectedEvt, got); diff != "" {
				t.Errorf("unexpected event (-want +got):\n%s", diff)
			}
		})
	}
}

func TestKubeServiceCATemplateMapper_MapPodCertRequestToX509Template(t *testing.T) {
	testNamespace := "test-ns"

	tests := []struct {
		name             string
		skipServiceCache bool
		pcr              *certv1.PodCertificateRequest
		pod              *corev1.Pod
		svc              *corev1.Service
		wantCert         *x509.Certificate
		wantLifetime     time.Duration // zero means the default of 1 hour set by newPCRBuilder
		wantEvent        *SigningErrorEvent
		wantErr          bool
	}{
		{
			name: "pod requesting an existing service",
			pcr:  newPCRBuilder(t, testNamespace).WithServices("my-svc").B(),
			pod: &corev1.Pod{
				Name: "my-pod", Namespace: testNamespace,
				Labels: map[string]string{"app": "foo"},
			},
			svc: &corev1.Service{
				Name: "my-svc", Namespace: testNamespace,
				Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "foo"}},
			},
			wantCert: &x509.Certificate{
				DNSNames: []string{"my-svc.test-ns.svc.nondefault.domain"},
				KeyUsage: x509.KeyUsageDigitalSignature,
			},
		},
		{
			name:             "pod requesting a service absent from the cache",
			skipServiceCache: true,
			pcr:              newPCRBuilder(t, testNamespace).WithServices("my-svc").B(),
			pod: &corev1.Pod{
				Name: "my-pod", Namespace: testNamespace,
				Labels: map[string]string{"app": "foo"},
			},
			svc: &corev1.Service{
				Name: "my-svc", Namespace: testNamespace,
				Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "foo"}},
			},
			wantCert: &x509.Certificate{
				DNSNames: []string{"my-svc.test-ns.svc.nondefault.domain"},
				KeyUsage: x509.KeyUsageDigitalSignature,
			},
		},
		{
			name: "pod requesting a nonexistent service",
			pcr:  newPCRBuilder(t, testNamespace).WithServices("my-svc").B(),
			pod:  &corev1.Pod{Name: "my-pod", Namespace: testNamespace},
			wantEvent: &SigningErrorEvent{
				Reason:  refServiceNotFoundReason,
				Message: `service "my-svc" for the pod not found`,
			},
		},
		{
			name: "pod requesting a service in another namespace",
			pcr:  newPCRBuilder(t, testNamespace).WithServices("my-svc").B(),
			pod: &corev1.Pod{
				Name: "my-pod", Namespace: testNamespace,
				Labels: map[string]string{"app": "foo"},
			},
			svc: &corev1.Service{
				Name: "my-svc", Namespace: "other-ns",
				Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "foo"}},
			},
			wantEvent: &SigningErrorEvent{
				Reason:  refServiceNotFoundReason,
				Message: `service "my-svc" for the pod not found`,
			},
		},
		{
			name: "pod not matching the service selector",
			pcr:  newPCRBuilder(t, testNamespace).WithServices("my-svc").B(),
			pod: &corev1.Pod{
				Name: "my-pod", Namespace: testNamespace,
				Labels: map[string]string{"app": "bar"},
			},
			svc: &corev1.Service{
				Name: "my-svc", Namespace: testNamespace,
				Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "foo"}},
			},
			wantEvent: &SigningErrorEvent{
				Reason:  serviceLabelsNotMatchedReason,
				Message: `pod does not match "my-svc" service's selector`,
			},
		},
		{
			name: "pod requesting a service without a selector",
			pcr:  newPCRBuilder(t, testNamespace).WithServices("my-svc").B(),
			pod:  &corev1.Pod{Name: "my-pod", Namespace: testNamespace},
			svc:  &corev1.Service{Name: "my-svc", Namespace: testNamespace},
			wantEvent: &SigningErrorEvent{
				Reason:  serviceLabelsNotMatchedReason,
				Message: `pod does not match "my-svc" service's selector`,
			},
		},
		{
			name: "pod requesting the same service multiple times",
			pcr:  newPCRBuilder(t, testNamespace).WithServices("my-svc", "my-svc").B(),
			pod: &corev1.Pod{
				Name: "my-pod", Namespace: testNamespace,
				Labels: map[string]string{"app": "foo"},
			},
			svc: &corev1.Service{
				Name: "my-svc", Namespace: testNamespace,
				Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "foo"}},
			},
			wantCert: &x509.Certificate{
				DNSNames: []string{"my-svc.test-ns.svc.nondefault.domain"},
				KeyUsage: x509.KeyUsageDigitalSignature,
			},
		},
		{
			name: "pod requesting an existing and a nonexistent service",
			pcr:  newPCRBuilder(t, testNamespace).WithServices("my-svc", "missing-svc").B(),
			pod: &corev1.Pod{
				Name: "my-pod", Namespace: testNamespace,
				Labels: map[string]string{"app": "foo"},
			},
			svc: &corev1.Service{
				Name: "my-svc", Namespace: testNamespace,
				Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "foo"}},
			},
			wantEvent: &SigningErrorEvent{
				Reason:  refServiceNotFoundReason,
				Message: `service "missing-svc" for the pod not found`,
			},
		},
		{
			name: "pod requesting its FQDN using its name",
			pcr:  newPCRBuilder(t, testNamespace).WithFQDN().B(),
			pod: &corev1.Pod{
				Name: "my-pod", Namespace: testNamespace,
				Spec: corev1.PodSpec{Subdomain: "my-subdomain"},
			},
			wantCert: &x509.Certificate{
				DNSNames: []string{"my-pod.my-subdomain.test-ns.svc.nondefault.domain"},
				KeyUsage: x509.KeyUsageDigitalSignature,
			},
		},
		{
			name: "pod requesting its FQDN using an explicit hostname",
			pcr:  newPCRBuilder(t, testNamespace).WithFQDN().B(),
			pod: &corev1.Pod{
				Name: "my-pod", Namespace: testNamespace,
				Spec: corev1.PodSpec{Hostname: "my-host", Subdomain: "my-subdomain"},
			},
			wantCert: &x509.Certificate{
				DNSNames: []string{"my-host.my-subdomain.test-ns.svc.nondefault.domain"},
				KeyUsage: x509.KeyUsageDigitalSignature,
			},
		},
		{
			name: "pod requesting both its FQDN and a service",
			pcr:  newPCRBuilder(t, testNamespace).WithFQDN().WithServices("my-svc").B(),
			pod: &corev1.Pod{
				Name: "my-pod", Namespace: testNamespace,
				Labels: map[string]string{"app": "foo"},
				Spec:   corev1.PodSpec{Subdomain: "my-subdomain"},
			},
			svc: &corev1.Service{
				Name: "my-svc", Namespace: testNamespace,
				Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "foo"}},
			},
			wantCert: &x509.Certificate{
				DNSNames: []string{
					"my-pod.my-subdomain.test-ns.svc.nondefault.domain",
					"my-svc.test-ns.svc.nondefault.domain",
				},
				KeyUsage: x509.KeyUsageDigitalSignature,
			},
		},
		{
			name:    "pod requesting its FQDN without a subdomain",
			pcr:     newPCRBuilder(t, testNamespace).WithFQDN().B(),
			pod:     &corev1.Pod{Name: "my-pod", Namespace: testNamespace},
			wantErr: true,
		},
		{
			name:    "pod requesting neither its FQDN nor services",
			pcr:     newPCRBuilder(t, testNamespace).B(),
			pod:     &corev1.Pod{Name: "my-pod", Namespace: testNamespace},
			wantErr: true,
		},
		{
			name: "requested expiration below the signer maximum is honored",
			pcr:  newPCRBuilder(t, testNamespace).WithFQDN().WithRequestMaxExpiration(1800).B(),
			pod: &corev1.Pod{
				Name: "my-pod", Namespace: testNamespace,
				Spec: corev1.PodSpec{Subdomain: "my-subdomain"},
			},
			wantCert: &x509.Certificate{
				DNSNames: []string{"my-pod.my-subdomain.test-ns.svc.nondefault.domain"},
				KeyUsage: x509.KeyUsageDigitalSignature,
			},
			wantLifetime: 30 * time.Minute,
		},
		{
			name: "requested expiration above the signer maximum is capped",
			pcr:  newPCRBuilder(t, testNamespace).WithFQDN().WithRequestMaxExpiration(30 * 24 * 60 * 60).B(),
			pod: &corev1.Pod{
				Name: "my-pod", Namespace: testNamespace,
				Spec: corev1.PodSpec{Subdomain: "my-subdomain"},
			},
			wantCert: &x509.Certificate{
				DNSNames: []string{"my-pod.my-subdomain.test-ns.svc.nondefault.domain"},
				KeyUsage: x509.KeyUsageDigitalSignature,
			},
			wantLifetime: signerMaxExpirationSeconds * time.Second,
		},
		{
			name: "RSA key request adds key encipherment usage",
			pcr:  newPCRBuilder(t, testNamespace).WithFQDN().WithCSR(rsaCSR(t)).B(),
			pod: &corev1.Pod{
				Name: "my-pod", Namespace: testNamespace,
				Spec: corev1.PodSpec{Subdomain: "my-subdomain"},
			},
			wantCert: &x509.Certificate{
				DNSNames: []string{"my-pod.my-subdomain.test-ns.svc.nondefault.domain"},
				KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			},
		},
		{
			name: "malformed stub PKCS#10 request",
			pcr:  newPCRBuilder(t, testNamespace).WithFQDN().WithCSR([]byte("not a csr")).B(),
			pod: &corev1.Pod{
				Name: "my-pod", Namespace: testNamespace,
				Spec: corev1.PodSpec{Subdomain: "my-subdomain"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []runtime.Object{}
			if tt.svc != nil {
				objs = append(objs, tt.svc)
			}
			fakeClient := fake.NewClientset(objs...)
			listerIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			if tt.svc != nil && !tt.skipServiceCache {
				_ = listerIndexer.Add(tt.svc)
			}
			svcLister := corev1listers.NewServiceLister(listerIndexer)

			m := NewKubeServiceCATemplateMapper(fakeClient.CoreV1(), &alwaysSyncedInformer{}, svcLister, "nondefault.domain")
			gotTmpl, gotEvent, gotErr := m.MapPodCertRequestToX509Template(t.Context(), tt.pcr, tt.pod)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("MapPodCertRequestToX509Template() failed unexpectedly: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("MapPodCertRequestToX509Template() succeeded unexpectedly")
			}
			if diff := cmp.Diff(tt.wantEvent, gotEvent); diff != "" {
				t.Errorf("unexpected event (-want +got):\n%s", diff)
			}

			if tt.wantCert == nil {
				if gotTmpl != nil {
					t.Errorf("expected no certificate template, got %+v", gotTmpl)
				}
				return
			}

			if gotTmpl == nil {
				t.Fatal("expected a certificate template, got nil")
			}

			// Serial number, validity and public key are generated per call, so they're not compared.
			if diff := cmp.Diff(tt.wantCert.DNSNames, gotTmpl.DNSNames); diff != "" {
				t.Errorf("unexpected DNSNames (-want +got):\n%s", diff)
			}
			if tt.wantCert.KeyUsage != gotTmpl.KeyUsage {
				t.Errorf("expected KeyUsage %v, got %v", tt.wantCert.KeyUsage, gotTmpl.KeyUsage)
			}
			if diff := cmp.Diff([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, gotTmpl.ExtKeyUsage); diff != "" {
				t.Errorf("unexpected ExtKeyUsage (-want +got):\n%s", diff)
			}
			wantLifetime := tt.wantLifetime
			if wantLifetime == 0 {
				wantLifetime = time.Hour
			}
			if got := gotTmpl.NotAfter.Sub(gotTmpl.NotBefore); got != wantLifetime {
				t.Errorf("expected certificate lifetime %v, got %v", wantLifetime, got)
			}
		})
	}
}

type alwaysSyncedInformer struct{ cache.SharedIndexInformer }

type pcrBuilder struct {
	*certv1.PodCertificateRequest
}

func newPCRBuilder(t *testing.T, namespace string) *pcrBuilder {

	return &pcrBuilder{
		PodCertificateRequest: &certv1.PodCertificateRequest{
			Name: "pcr-req", Namespace: namespace,
			Spec: certv1.PodCertificateRequestSpec{
				MaxExpirationSeconds:      new(int32(3600)),
				StubPKCS10Request:         eccCSR(t),
				UnverifiedUserAnnotations: map[string]string{},
			},
		},
	}
}

func (b *pcrBuilder) WithRequestMaxExpiration(seconds int32) *pcrBuilder {
	b.Spec.MaxExpirationSeconds = new(seconds)
	return b
}

func (b *pcrBuilder) WithCSR(csr []byte) *pcrBuilder {
	b.Spec.StubPKCS10Request = csr
	return b
}

func (b *pcrBuilder) WithServices(s ...string) *pcrBuilder {
	if len(s) == 0 {
		return b
	}

	servicesString := strings.Join(s, ",")
	b.Spec.UnverifiedUserAnnotations[ServiceNamesKey] = servicesString
	return b
}

func (b *pcrBuilder) WithFQDN() *pcrBuilder {
	b.Spec.UnverifiedUserAnnotations[AddPodFQDNKey] = "true"
	return b
}

func (b *pcrBuilder) B() *certv1.PodCertificateRequest {
	return b.PodCertificateRequest
}

func (*alwaysSyncedInformer) HasSynced() bool {
	return true
}

func eccCSR(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA P-521 key: %v", err)
	}
	return signStubCSR(t, key)
}

func rsaCSR(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return signStubCSR(t, key)
}

func signStubCSR(t *testing.T, key crypto.Signer) []byte {
	t.Helper()

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("failed to create stub PKCS#10 request: %v", err)
	}
	return csr
}
