```
go mod download
cp credentials{.sample,}.json
# edit credentials.json
go run ./cmd/hatena-oauth-token/ -port 8888 -owner $blog_owner_hatena_id -domain $blog_domain
```
