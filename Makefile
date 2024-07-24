deploy:
	GOFLAGS="-buildvcs=false -trimpath '-ldflags=-s -w -buildid='" sam build --parallel
	sam deploy \
		--stack-name awsid \
		--capabilities CAPABILITY_IAM \
		--resolve-s3 \
		--no-fail-on-empty-changeset
