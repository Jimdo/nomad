package vaultclient

import (
	"container/heap"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/hashicorp/nomad/nomad/structs/config"
	vaultapi "github.com/hashicorp/vault/api"
	vaultduration "github.com/hashicorp/vault/helper/duration"
)

type VaultClient interface {
	Start()
	Stop()
	DeriveToken() (string, error)
	GetConsulACL(string, string) (*vaultapi.Secret, error)
	RenewToken(string) <-chan error
	StopRenewToken(string) error
	RenewLease(string, int) <-chan error
	StopRenewLease(string) error
}

type vaultClient struct {
	running        bool
	token          string
	taskTokenTTL   string
	vaultAPIClient *vaultapi.Client
	updateCh       chan struct{}
	stopCh         chan struct{}
	heap           *vaultClientHeap
	lock           sync.RWMutex
	logger         *log.Logger
}

type vaultClientRenewalRequest struct {
	errCh    chan error
	id       string
	duration int
	isToken  bool
}

type vaultClientHeapEntry struct {
	req   *vaultClientRenewalRequest
	next  time.Time
	index int
}

type vaultClientHeap struct {
	heapMap map[string]*vaultClientHeapEntry
	heap    vaultDataHeapImp
}

type vaultDataHeapImp []*vaultClientHeapEntry

func NewVaultClient(vaultConfig *config.VaultConfig, logger *log.Logger) (*vaultClient, error) {
	if vaultConfig == nil {
		return nil, fmt.Errorf("nil, vaultConfig")
	}
	if vaultConfig.Token == "" {
		return nil, fmt.Errorf("periodic_token not set")
	}

	return &vaultClient{
		token:        vaultConfig.Token,
		taskTokenTTL: vaultConfig.TaskTokenTTL,
		stopCh:       make(chan struct{}),
		updateCh:     make(chan struct{}, 1),
		heap:         NewVaultDataHeap(),
		logger:       logger,
	}, nil
}

func NewVaultDataHeap() *vaultClientHeap {
	return &vaultClientHeap{
		heapMap: make(map[string]*vaultClientHeapEntry),
		heap:    make(vaultDataHeapImp, 0),
	}
}

func (c *vaultClient) IsTracked(id string) bool {
	_, ok := c.heap.heapMap[id]
	return ok
}

func (c *vaultClient) Start() {
	c.logger.Printf("[INFO] vaultClient started")
	c.lock.Lock()
	c.running = true
	c.lock.Unlock()
	go c.run()
}

func (c *vaultClient) Stop() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.running = false
	close(c.stopCh)
}

func (c *vaultClient) DeriveToken() (string, error) {
	tcr := &vaultapi.TokenCreateRequest{
		Policies:    []string{"foo", "bar"},
		TTL:         "10s",
		DisplayName: "derived-for-task",
		Renewable:   new(bool),
	}
	*tcr.Renewable = true

	client, err := c.getVaultAPIClient()
	if err != nil {
		return "", fmt.Errorf("failed to create vault API client: %v", err)
	}

	wrapLookupFunc := func(method, path string) string {
		if method == "POST" && path == "auth/token/create" {
			return "60s"
		}
		return ""
	}
	client.SetWrappingLookupFunc(wrapLookupFunc)

	secret, err := client.Auth().Token().Create(tcr)
	if err != nil {
		return "", fmt.Errorf("failed to create vault token: %v", err)
	}
	if secret == nil || secret.WrapInfo == nil || secret.WrapInfo.Token == "" ||
		secret.WrapInfo.WrappedAccessor == "" {
		return "", fmt.Errorf("failed to derive a wrapped vault token")
	}

	wrappedToken := secret.WrapInfo.Token

	unwrapResp, err := client.Logical().Unwrap(wrappedToken)
	if err != nil {
		return "", fmt.Errorf("failed to unwrap the token: %v", err)
	}
	if unwrapResp == nil || unwrapResp.Auth == nil || unwrapResp.Auth.ClientToken == "" {
		return "", fmt.Errorf("failed to unwrap the token")
	}

	return unwrapResp.Auth.ClientToken, nil
}

func (c *vaultClient) GetConsulACL(token, vaultPath string) (*vaultapi.Secret, error) {
	c.logger.Printf("[INFO] GetConsulACL called with token: %s, vaultPath: %s", token, vaultPath)
	if token == "" {
		return nil, fmt.Errorf("missing token")
	}
	if vaultPath == "" {
		return nil, fmt.Errorf("missing vault path")
	}

	client, err := c.getVaultAPIClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create vault API client: %v", err)
	}
	client.SetToken(token)

	return client.Logical().Read(vaultPath)
}

func (c *vaultClient) RenewToken(token string) <-chan error {
	errCh := make(chan error, 1)

	if token == "" {
		errCh <- fmt.Errorf("missing token")
		return errCh
	}

	increment, err := vaultduration.ParseDurationSecond(c.taskTokenTTL)
	if err != nil {
		errCh <- fmt.Errorf("failed to parse task_token_ttl:%v", err)
		return errCh
	}
	// Convert increment to seconds
	increment /= time.Second

	renewalReq := &vaultClientRenewalRequest{
		errCh:    errCh,
		id:       token,
		isToken:  true,
		duration: int(increment),
	}

	if err := c.renew(renewalReq); err != nil {
		errCh <- err
	}

	return errCh
}

func (c *vaultClient) RenewLease(leaseId string, leaseDuration int) <-chan error {
	errCh := make(chan error, 1)

	if leaseId == "" {
		errCh <- fmt.Errorf("missing lease ID")
		return errCh
	}

	if leaseDuration == 0 {
		errCh <- fmt.Errorf("missing lease duration")
		return errCh
	}

	renewalReq := &vaultClientRenewalRequest{
		errCh:    make(chan error, 1),
		id:       leaseId,
		duration: leaseDuration,
	}

	if err := c.renew(renewalReq); err != nil {
		errCh <- err
	}

	return errCh
}

func (c *vaultClient) renew(req *vaultClientRenewalRequest) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if req == nil {
		return fmt.Errorf("nil renewal request")
	}
	if req.id == "" {
		return fmt.Errorf("missing id in renewal request")
	}

	client, err := c.getVaultAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create vault API client: %v", err)
	}

	var duration time.Duration
	if req.isToken {
		renewResp, err := client.Auth().Token().Renew(req.id, req.duration)
		if err != nil {
			return fmt.Errorf("failed to renew the vault token: %v", err)
		}
		if renewResp == nil || renewResp.Auth == nil {
			return fmt.Errorf("failed to renew the vault token")
		}

		duration = time.Duration(renewResp.Auth.LeaseDuration) * time.Second / 2
	} else {
		renewResp, err := client.Sys().Renew(req.id, req.duration)
		if err != nil {
			return fmt.Errorf("failed to renew vault secret: %v", err)
		}
		if renewResp == nil {
			return fmt.Errorf("failed to renew vault secret")
		}
		duration = time.Duration(renewResp.LeaseDuration) * time.Second / 2
	}
	next := time.Now().Add(duration)

	if c.IsTracked(req.id) {
		if err := c.heap.Update(req, next); err != nil {
			return fmt.Errorf("failed to update heap entry. err: %v", err)
		}
	} else {
		if err := c.heap.Push(req, next); err != nil {
			return fmt.Errorf("failed to push an entry to heap.  err: %v", err)
		}
		// Signal an update.
		if c.running {
			select {
			case c.updateCh <- struct{}{}:
			default:
			}
		}
	}

	c.logger.Printf("[INFO] Renewal of %q complete", req.id)

	return nil
}

func (c *vaultClient) run() {
	var renewalCh <-chan time.Time
	for c.running {
		renewalReq, renewalTime := c.nextRenewal()
		if renewalTime.IsZero() {
			renewalCh = nil
		} else {
			now := time.Now()
			if renewalTime.After(now) {
				renewalDuration := renewalTime.Sub(time.Now())
				renewalCh = time.After(renewalDuration)
			} else {
				renewalCh = time.After(0)
			}
		}

		select {
		case <-renewalCh:
			if err := c.renew(renewalReq); err != nil {
				renewalReq.errCh <- err
			}
		case <-c.updateCh:
			continue
		case <-c.stopCh:
			c.logger.Printf("[INFO] vaultClient stopped")
			return
		}
	}
}

func (c *vaultClient) StopRenewToken(token string) error {
	if !c.IsTracked(token) {
		return nil
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if err := c.heap.Remove(token); err != nil {
		return fmt.Errorf("failed to remove heap entry: %v", err)
	}
	delete(c.heap.heapMap, token)

	// Signal an update.
	if c.running {
		select {
		case c.updateCh <- struct{}{}:
		default:
		}
	}

	return nil
}

func (c *vaultClient) StopRenewLease(string) error {
	return nil
}

func (c *vaultClient) nextRenewal() (*vaultClientRenewalRequest, time.Time) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if c.heap.Length() == 0 {
		return nil, time.Time{}
	}

	nextEntry := c.heap.Peek()
	if nextEntry == nil {
		return nil, time.Time{}
	}

	return nextEntry.req, nextEntry.next
}

func (c *vaultClient) getVaultAPIClient() (*vaultapi.Client, error) {
	if c.vaultAPIClient == nil {
		// Get the default configuration
		config := vaultapi.DefaultConfig()

		// Read the environment variables and update the configuration
		if err := config.ReadEnvironment(); err != nil {
			return nil, fmt.Errorf("failed to read the environment: %v", err)
		}

		// Create a Vault API Client
		client, err := vaultapi.NewClient(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create Vault client: %v", err)
		}

		// Set the authentication required
		client.SetToken(c.token)
		c.vaultAPIClient = client
	}

	return c.vaultAPIClient, nil
}

// The heap interface requires the following methods to be implemented.
// * Push(x interface{}) // add x as element Len()
// * Pop() interface{}   // remove and return element Len() - 1.
// * sort.Interface
//
// sort.Interface comprises of the following methods:
// * Len() int
// * Less(i, j int) bool
// * Swap(i, j int)

func (h vaultDataHeapImp) Len() int { return len(h) }

func (h vaultDataHeapImp) Less(i, j int) bool {
	// Two zero times should return false.
	// Otherwise, zero is "greater" than any other time.
	// (To sort it at the end of the list.)
	// Sort such that zero times are at the end of the list.
	iZero, jZero := h[i].next.IsZero(), h[j].next.IsZero()
	if iZero && jZero {
		return false
	} else if iZero {
		return false
	} else if jZero {
		return true
	}

	return h[i].next.Before(h[j].next)
}

func (h vaultDataHeapImp) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *vaultDataHeapImp) Push(x interface{}) {
	n := len(*h)
	entry := x.(*vaultClientHeapEntry)
	entry.index = n
	*h = append(*h, entry)
}

func (h *vaultDataHeapImp) Pop() interface{} {
	old := *h
	n := len(old)
	entry := old[n-1]
	entry.index = -1 // for safety
	*h = old[0 : n-1]
	return entry
}

// Helper functions on the struct which encapsulates the heap
func (h *vaultClientHeap) Length() int {
	return len(h.heap)
}

func (h *vaultClientHeap) Peek() *vaultClientHeapEntry {
	if len(h.heap) == 0 {
		return nil
	}

	return h.heap[0]
}

func (h *vaultClientHeap) Push(req *vaultClientRenewalRequest, next time.Time) error {
	if _, ok := h.heapMap[req.id]; ok {
		return fmt.Errorf("entry %v already exists", req.id)
	}

	heapEntry := &vaultClientHeapEntry{
		req:  req,
		next: next,
	}
	h.heapMap[req.id] = heapEntry
	heap.Push(&h.heap, heapEntry)
	return nil
}

func (h *vaultClientHeap) Update(req *vaultClientRenewalRequest, next time.Time) error {
	if entry, ok := h.heapMap[req.id]; ok {
		entry.req = req
		entry.next = next
		heap.Fix(&h.heap, entry.index)
		return nil
	}

	return fmt.Errorf("heap doesn't contain %v", req.id)
}

func (h *vaultClientHeap) Remove(id string) error {
	if entry, ok := h.heapMap[id]; ok {
		heap.Remove(&h.heap, entry.index)
		delete(h.heapMap, id)
		return nil
	}

	return fmt.Errorf("heap doesn't contain entry for %v", id)
}
