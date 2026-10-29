package gandi

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/go-gandi/go-gandi/domain"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceNameservers() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceNameserversCreate,
		Read:          resourceNameserversRead,
		UpdateContext: resourceNameserversUpdate,
		Delete:        resourceNameserversDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"domain": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The FQDN of the domain",
			},
			"nameservers": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "A list of nameservers for the domain",
			},
		},
		Timeouts: &schema.ResourceTimeout{Default: schema.DefaultTimeout(2 * time.Minute)},
	}
}

func resourceNameserversCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*clients).Domain

	domain := d.Get("domain").(string)
	d.SetId(domain)
	nameservers := expandArray(d.Get("nameservers").([]interface{}))

	if err := updateNameServers(ctx, client, domain, nameservers); err != nil {
		return diag.FromErr(err)
	}

	err := resource.RetryContext(ctx, d.Timeout(schema.TimeoutCreate), func() *resource.RetryError {
		return retryableGetNameServers(client, domain, nameservers)
	})
	if err != nil {
		return diag.FromErr(err)
	}
	return diag.FromErr(resourceNameserversRead(d, meta))
}

func resourceNameserversRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients).Domain
	domain := d.Id()
	nameservers, err := client.GetNameServers(domain)
	if err != nil {
		d.SetId("")
		return err
	}
	if err = d.Set("domain", domain); err != nil {
		return fmt.Errorf("failed to set domain name for %s: %w", d.Id(), err)
	}
	if err = d.Set("nameservers", nameservers); err != nil {
		return fmt.Errorf("failed to set nameservers for %s: %w", d.Id(), err)
	}
	return nil
}

func resourceNameserversUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*clients).Domain
	domain := d.Get("domain").(string)
	nameservers := expandArray(d.Get("nameservers").([]interface{}))

	if d.HasChange("nameservers") {
		if err := updateNameServers(ctx, client, domain, nameservers); err != nil {
			return diag.FromErr(err)
		}
	}
	err := resource.RetryContext(ctx, d.Timeout(schema.TimeoutCreate), func() *resource.RetryError {
		return retryableGetNameServers(client, domain, nameservers)
	})
	if err != nil {
		return diag.FromErr(err)
	}
	return diag.FromErr(resourceNameserversRead(d, meta))
}

// resourceNameserversDelete deletes the nameservers resource and
// re-enable the liveDNS nameserver on the domain, which is the
// default domain configurtion.
func resourceNameserversDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients).Domain
	domain := d.Id()
	// Removing nameservers consits of enabling livedns, which is
	// the initial domain state.
	if err := client.EnableLiveDNS(domain); err != nil {
		return err
	}
	d.SetId("")
	return nil
}

func retryableGetNameServers(client *domain.Domain, domain string, nameservers []string) *resource.RetryError {
	nameserversFromApi, err := client.GetNameServers(domain)
	if err != nil {
		return resource.NonRetryableError(
			fmt.Errorf("Error getting nameservers of domain %s: %s", domain, err))
	}
	if !reflect.DeepEqual(nameserversFromApi, nameservers) {
		return resource.RetryableError(fmt.Errorf("Nameservers on domain %s have not been applied yet", domain))
	}
	return nil
}

// How long to wait for Gandi to remove the DNSSEC keys of a domain after a
// change of nameservers.
const dnssecKeysRemovalTimeout = 30 * time.Second

// updateNameServers changes the nameservers of a domain. Gandi removes the
// DNSSEC keys of the domain when its nameservers change. They are created
// again.
func updateNameServers(ctx context.Context, client *domain.Domain, fqdn string, nameservers []string) error {
	current, err := client.GetNameServers(fqdn)
	if err != nil {
		return fmt.Errorf("Error getting nameservers of domain %s: %w", fqdn, err)
	}
	if reflect.DeepEqual(current, nameservers) {
		return nil
	}
	keys, err := client.ListDNSSECKeys(fqdn)
	if err != nil {
		return fmt.Errorf("Error getting DNSSEC keys of domain %s: %w", fqdn, err)
	}
	if err := client.UpdateNameServers(fqdn, nameservers); err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}

	var removed []domain.DNSSECKey
	deadline := time.Now().Add(dnssecKeysRemovalTimeout)
	for {
		remaining, err := client.ListDNSSECKeys(fqdn)
		if err != nil {
			return fmt.Errorf("Error getting DNSSEC keys of domain %s: %w", fqdn, err)
		}
		removed = missingDNSSECKeys(keys, remaining)
		if len(removed) == len(keys) || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	for _, k := range removed {
		request := domain.DNSSECKeyCreateRequest{
			Algorithm: k.Algorithm,
			Type:      k.Type,
			PublicKey: k.PublicKey,
		}
		if err := client.CreateDNSSECKey(fqdn, request); err != nil {
			return fmt.Errorf("Error restoring DNSSEC key %d of domain %s: %w", k.KeyTag, fqdn, err)
		}
	}
	return nil
}

// missingDNSSECKeys returns the keys not present in the second list.
func missingDNSSECKeys(keys []domain.DNSSECKey, others []domain.DNSSECKey) (missing []domain.DNSSECKey) {
	for _, k := range keys {
		found := false
		for _, o := range others {
			if o.PublicKey == k.PublicKey {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, k)
		}
	}
	return
}
