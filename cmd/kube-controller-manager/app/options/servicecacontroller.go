/*
Copyright 2026 The Kubernetes Authors.

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

package options

import (
	"github.com/spf13/pflag"

	podcertssignerconfig "k8s.io/kubernetes/pkg/controller/certificates/podcertssigner/config"
)

// ServiceServingSignerOptions holds the PodCertsSignerConfiguration options for the kube service CA signer.
type ServiceServingSignerOptions struct {
	*podcertssignerconfig.PodCertsSignerConfiguration
}

// AddFlags adds flags related to ServiceCASignerControllers for controller manager to the specified FlagSet
func (o *ServiceServingSignerOptions) AddFlags(fs *pflag.FlagSet) {
	if o == nil {
		return
	}

	if len(o.ServiceCABundlePath) == 0 {
		o.ClusterServiceDomain = "cluster.local"
	}

	fs.StringVar(&o.ServiceCACertPath, "service-serving-cert", o.ServiceCACertPath, "Path to the signer cert for the service serving signer. Expects PEM format. If there are multiple certificates in the bundle, the first one is used.")
	fs.StringVar(&o.ServiceCAKeyPath, "service-serving-key", o.ServiceCAKeyPath, "Path to the signer key for the service serving signer. Expects a single key in PEM format.")
	fs.StringVar(&o.ServiceCABundlePath, "service-serving-trust-bundle", o.ServiceCABundlePath, "Path to the trust bundle for the service serving signer. Used for trust distrubution within the cluster. Expects PEM format.")
	fs.StringVar(&o.ClusterServiceDomain, "cluster-service-domain", o.ClusterServiceDomain, "Cluster's service domain name. Defaults to 'cluster.local'.")
}

// ApplyTo fills up PodCertsSignerConfiguration config with options.
func (o *ServiceServingSignerOptions) ApplyTo(cfg *podcertssignerconfig.PodCertsSignerConfiguration) error {
	if o == nil {
		return nil
	}

	cfg.ServiceCACertPath = o.ServiceCACertPath
	cfg.ServiceCAKeyPath = o.ServiceCAKeyPath
	cfg.ServiceCABundlePath = o.ServiceCABundlePath
	cfg.ClusterServiceDomain = o.ClusterServiceDomain

	return nil
}

// Validate checks validation of ServiceAccountControllerOptions.
func (o *ServiceServingSignerOptions) Validate() []error {
	if o == nil {
		return nil
	}

	// FIXME: validate both cert/key are set if at least one is set, validate
	// cluster domain is set

	errs := []error{}
	return errs
}
