package main

import (
	"context"
	"fmt"
	"log"

	"github.com/anagovbr/azure-batch-made/app/auth"
)

func main() {
	ctx := context.TODO()
	entraId, err := auth.NewEntraIdService(ctx)
	if err != nil {
		log.Printf("failed to instanciate EntraIdService: %v", err)
	}
	token, err := entraId.GetBatchToken(ctx)
	if err != nil {
		log.Printf("failed to get batch token: %v", err)
	}
	fmt.Println(token)
}
