package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/lambdaurl"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/smithy-go"
)

var ErrNoSuchPrincipal = errors.New("no such principal")

//go:embed html
var htmlFs embed.FS

func main() {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		panic(err)
	}

	h := &handler{
		api:       s3control.NewFromConfig(cfg),
		accountId: os.Getenv("ACCOUNT_ID"),
		bucket:    os.Getenv("BUCKET"),
	}

	sub, _ := fs.Sub(htmlFs, "html")

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServerFS(sub))
	mux.HandleFunc("/id/{id}", h.handleUniqueIdLookup)

	if _, ok := os.LookupEnv("AWS_LAMBDA_FUNCTION_NAME"); ok {
		lambdaurl.Start(mux)
	} else {
		http.ListenAndServe(":8080", mux)
	}
}

type handler struct {
	api       *s3control.Client
	accountId string
	bucket    string
}

func (h *handler) handleUniqueIdLookup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	uniqueId := r.PathValue("id")
	arn, err := h.uniqueIdToArn(ctx, uniqueId)

	fields := map[string]any{
		"uid": uniqueId,
		"arn": arn,
		"ip":  r.Header.Get("X-Forwarded-For"),
		"cc":  r.Header.Get("Cloudfront-Viewer-Country"),
		"ua":  r.UserAgent(),
	}
	if err != nil {
		fields["err"] = err.Error()
	}

	logj, _ := json.Marshal(fields)
	fmt.Println(string(logj))

	if err != nil {
		if errors.Is(err, ErrNoSuchPrincipal) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintln(w, "no such principal found")
			return
		}

		panic(err)
	}

	acceptType := r.Header.Get("Accept")
	if acceptType == "application/json" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		j, _ := json.Marshal(map[string]any{"Principal": arn})
		w.Write(j)
	} else {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, arn)
	}
}

func (h *handler) uniqueIdToArn(ctx context.Context, id string) (string, error) {
	accessPointName := fmt.Sprintf("awsid-%d", rand.Int31())

	create, err := h.api.CreateAccessPoint(ctx, &s3control.CreateAccessPointInput{
		AccountId: &h.accountId,
		Bucket:    &h.bucket,
		Name:      &accessPointName,
	})
	if err != nil {
		return "", fmt.Errorf("creating access point: %w", err)
	}

	defer h.api.DeleteAccessPoint(ctx, &s3control.DeleteAccessPointInput{
		AccountId: &h.accountId,
		Name:      &accessPointName,
	})

	policy := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "Statement1",
				"Effect": "Deny",
				"Principal": {
					"AWS": "%s"
				},
				"Action": "*",
				"Resource": "%s"
			}
		]
	}`, id, *create.AccessPointArn)

	_, err = h.api.PutAccessPointPolicy(ctx, &s3control.PutAccessPointPolicyInput{
		AccountId: &h.accountId,
		Name:      &accessPointName,
		Policy:    &policy,
	})
	if err != nil {
		var oe smithy.APIError
		if errors.As(err, &oe) && oe.ErrorCode() == "MalformedPolicy" {
			return "", ErrNoSuchPrincipal
		}

		return "", fmt.Errorf("putting access point policy: %w", err)
	}

	get, err := h.api.GetAccessPointPolicy(ctx, &s3control.GetAccessPointPolicyInput{
		AccountId: &h.accountId,
		Name:      &accessPointName,
	})
	if err != nil {
		return "", fmt.Errorf("retrieving access point policy: %w", err)
	}

	pj := policyJson{}
	err = json.Unmarshal([]byte(*get.Policy), &pj)
	if err != nil {
		return "", fmt.Errorf("parsing policy json: %w", err)
	}

	return pj.Statement[0].Principal.AWS, nil
}

type policyJson struct {
	Version   string `json:"Version"`
	Statement []struct {
		Sid       string `json:"Sid"`
		Effect    string `json:"Effect"`
		Principal struct {
			AWS string `json:"AWS"`
		} `json:"Principal"`
		Action   string `json:"Action"`
		Resource string `json:"Resource"`
	} `json:"Statement"`
}
