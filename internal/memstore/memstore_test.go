package memstore_test

import (
	"testing"

	"github.com/acneism/limb/internal/memstore"
	"github.com/acneism/limb/store"
	"github.com/acneism/limb/store/storetest"
)

func TestStoreCompatibility(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store {
		return memstore.New()
	})
}
