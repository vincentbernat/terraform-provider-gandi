package gandi

import (
	"reflect"
	"testing"

	"github.com/go-gandi/go-gandi/domain"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccNameservers_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		Providers:  testAccProviders,
		PreCheck:   func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccConfigNameservers(),
			},
		},
	})
}

func testAccConfigNameservers() string {
	return `
	  resource "gandi_nameservers" "terraform_provider_gandi_com" {
	    domain = "terraform-provider-gandi.com"
            nameservers = ["ns1.example.foo", "ns2.example.foo"]
          }
	`
}

func TestMissingDNSSECKeys(t *testing.T) {
	k1 := domain.DNSSECKey{ID: 1, PublicKey: "key1"}
	k2 := domain.DNSSECKey{ID: 2, PublicKey: "key2"}
	k2bis := domain.DNSSECKey{ID: 3, PublicKey: "key2"}
	cases := []struct {
		keys, others, expected []domain.DNSSECKey
	}{
		{[]domain.DNSSECKey{k1, k2}, []domain.DNSSECKey{k1, k2}, nil},
		{[]domain.DNSSECKey{k1, k2}, nil, []domain.DNSSECKey{k1, k2}},
		{[]domain.DNSSECKey{k1, k2}, []domain.DNSSECKey{k2bis}, []domain.DNSSECKey{k1}},
	}
	for _, c := range cases {
		got := missingDNSSECKeys(c.keys, c.others)
		if !reflect.DeepEqual(got, c.expected) {
			t.Fatalf("missingDNSSECKeys(%v, %v) = %v, expected %v", c.keys, c.others, got, c.expected)
		}
	}
}
