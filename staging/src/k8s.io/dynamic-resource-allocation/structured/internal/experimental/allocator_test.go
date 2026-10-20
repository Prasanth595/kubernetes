/*
Copyright 2025 The Kubernetes Authors.

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

package experimental_test

import (
	"context"
	"testing"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/dynamic-resource-allocation/cel"
	"k8s.io/dynamic-resource-allocation/structured"
	"k8s.io/dynamic-resource-allocation/structured/internal"
	"k8s.io/dynamic-resource-allocation/structured/internal/allocatortesting"
	"k8s.io/dynamic-resource-allocation/structured/internal/experimental"
	"k8s.io/dynamic-resource-allocation/structured/schedulerapi"
	"k8s.io/klog/v2/ktesting"
)

var (
	_ structured.AffinityAllocator          = (*experimental.Allocator)(nil)
	_ *internal.ClaimAffinity               = (*structured.ClaimAffinity)(nil)
	_ *internal.ClaimAffinity               = (*experimental.ClaimAffinity)(nil)
	_ *internal.DeviceAffinity              = (*structured.DeviceAffinity)(nil)
	_ *internal.DeviceAffinity              = (*experimental.DeviceAffinity)(nil)
	_ *internal.PoolMetadataView            = (*structured.PoolMetadataView)(nil)
	_ *internal.PoolMetadataView            = (*experimental.PoolMetadataView)(nil)
	_ *schedulerapi.AffinityStatus          = (*structured.AffinityStatus)(nil)
	_ *schedulerapi.AffinityStatus          = (*internal.AffinityStatus)(nil)
	_ *schedulerapi.DeviceAffinityState     = (*structured.DeviceAffinityState)(nil)
	_ *schedulerapi.DeviceAffinityState     = (*internal.DeviceAffinityState)(nil)
	_ *schedulerapi.AffinityStateCollection = (*structured.AffinityStateCollection)(nil)
	_ *schedulerapi.AffinityStateCollection = (*internal.AffinityStateCollection)(nil)
	_ *schedulerapi.SharingAffinityState    = (*structured.SharingAffinityState)(nil)
	_ *schedulerapi.SharingAffinityState    = (*internal.SharingAffinityState)(nil)
	_ *schedulerapi.AllocatedState          = (*structured.AllocatedState)(nil)
	_ *schedulerapi.AllocatedState          = (*internal.AllocatedState)(nil)
)

func TestSharingAffinityStatusAliases(t *testing.T) {
	for _, statuses := range [][3]schedulerapi.AffinityStatus{
		{structured.AffinityStatusClean, internal.AffinityStatusClean, schedulerapi.AffinityStatusClean},
		{structured.AffinityStatusLocked, internal.AffinityStatusLocked, schedulerapi.AffinityStatusLocked},
		{structured.AffinityStatusUnreconstructable, internal.AffinityStatusUnreconstructable, schedulerapi.AffinityStatusUnreconstructable},
	} {
		if statuses[0] != statuses[2] || statuses[1] != statuses[2] {
			t.Errorf("status aliases = %d/%d, want %d", statuses[0], statuses[1], statuses[2])
		}
	}
}

func TestSharingAffinityFeaturesAll(t *testing.T) {
	t.Cleanup(func() { structured.EnableAllocators() })
	t.Run("feature sets", func(t *testing.T) {
		if !internal.FeaturesAll.SharingAffinity || !internal.FeaturesAll.Set().Has("DRASharingAffinity") {
			t.Error("FeaturesAll must enable and advertise DRASharingAffinity")
		}
		for _, enabled := range []bool{false, true} {
			if got := (internal.Features{SharingAffinity: enabled}).Set().Has("DRASharingAffinity"); got != enabled {
				t.Errorf("Features{SharingAffinity:%t}.Set contains gate = %t", enabled, got)
			}
		}
	})
	for _, tc := range []struct {
		name     string
		channels []string
		wantErr  bool
	}{
		{"stable", []string{"stable"}, true},
		{"incubating", []string{"incubating"}, true},
		{"older implementations", []string{"stable", "incubating"}, true},
		{"experimental", []string{"experimental"}, false},
		{"default selection", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ctx := ktesting.NewTestContext(t)
			structured.EnableAllocators(tc.channels...)
			allocator, err := structured.NewAllocator(ctx, internal.Features{ConsumableCapacity: true, SharingAffinity: true}, structured.AllocatedState{}, nil, nil, nil)
			if tc.wantErr {
				if err == nil || allocator != nil {
					t.Errorf("unsupported constructor = (%T, %v), want nil allocator and error", allocator, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("constructor: %v", err)
			}
			actual, ok := allocator.(internal.Allocator)
			if !ok {
				t.Fatalf("allocator %T does not expose its implementation channel", allocator)
			}
			if got := actual.Channel(); got != internal.Experimental {
				t.Errorf("channel = %q, want experimental", got)
			}
		})
	}
}

func TestAllocator(t *testing.T) {
	newAllocator := func(
		ctx context.Context,
		features internal.Features,
		allocatedState internal.AllocatedState,
		classLister internal.DeviceClassLister,
		slices []*resourceapi.ResourceSlice,
		celCache *cel.Cache,
	) (internal.Allocator, error) {
		return experimental.NewAllocator(ctx, features, allocatedState, classLister, slices, celCache)
	}
	allocatortesting.TestAllocator(t,
		experimental.SupportedFeatures,
		newAllocator,
	)
	allocatortesting.TestLexicographicalAllocator(t,
		experimental.SupportedFeatures,
		newAllocator,
	)
}
