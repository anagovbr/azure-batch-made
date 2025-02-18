package auth

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity/cache"
)

const record_path = "auth.json"

type EntraIdService struct {
	credential *azidentity.InteractiveBrowserCredential
}

func retrieveRecord(path string) (azidentity.AuthenticationRecord, error) {
	record := azidentity.AuthenticationRecord{}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return record, nil
		}
	} else {
		err = json.Unmarshal(b, &record)
	}
	return record, err
}

func storeRecord(record azidentity.AuthenticationRecord, path string) error {
	b, err := json.Marshal(record)
	if err == nil {
		err = os.WriteFile(path, b, 0600)
	}
	return err
}

func (e *EntraIdService) GetStorageToken(ctx context.Context) (string, error) {
	token, err := e.credential.GetToken(
		ctx,
		policy.TokenRequestOptions{Scopes: []string{"https://storage.azure.com/.default"}},
	)
	if err != nil {
		return "", nil
	}
	return token.Token, nil
}

func (e *EntraIdService) GetBatchToken(ctx context.Context) (string, error) {
	token, err := e.credential.GetToken(
		ctx,
		policy.TokenRequestOptions{Scopes: []string{"https://batch.core.windows.net/.default"}},
	)
	if err != nil {
		return "", nil
	}
	return token.Token, nil
}

func NewEntraIdService(ctx context.Context, path ...string) (*EntraIdService, error) {
	p := record_path
	if len(path) > 0 {
		p = path[0]
	}

	record, err := retrieveRecord(p)
	if err != nil {
		return nil, err
	}

	cache, err := cache.New(nil)
	if err != nil {
		return nil, err
	}

	cred, err := azidentity.NewInteractiveBrowserCredential(&azidentity.InteractiveBrowserCredentialOptions{
		AuthenticationRecord: record,
		Cache:                cache,
	})
	if err != nil {
		return nil, err
	}

	if record == (azidentity.AuthenticationRecord{}) {
		record, err := cred.Authenticate(ctx, nil)
		if err != nil {
			return nil, err
		}
		err = storeRecord(record, p)
		if err != nil {
			return nil, err
		}
	}

	return &EntraIdService{credential: cred}, nil
}
