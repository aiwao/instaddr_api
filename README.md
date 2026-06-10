[![Go Reference](https://pkg.go.dev/badge/github.com/aiwao/instaddr_api.svg)](https://pkg.go.dev/github.com/aiwao/instaddr_api)
# instaddr_api
api wrapper of "m.kuku.lu"

## Client
```go
ctx := context.Background()

client := instaddr.NewClient(instaddr.ClientOptions{
    HTTPClient: http.DefaultClient,
    UserAgent:  "Mozilla...",
})

acc, err := client.NewAccount(ctx)
if err != nil ...
```

If you don't set `HTTPClient`, `http.DefaultClient` will be used.

If you don't set `UserAgent`, the user-agent will be random. If you set `RandomUserAgent` to true, the user-agent will also be random.

```go
client := instaddr.NewClient(instaddr.ClientOptions{
    RandomUserAgent: true,
})
```

You can also use the package-level default client.

```go
acc, err := instaddr.NewAccount(ctx)
if err != nil ...
```

## Context
```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

acc, err := client.NewAccount(ctx)
if err != nil ...
```

## Login to account
```go
acc, err := client.LoginAccount(ctx, instaddr.AuthInfo{"AccountID", "Password"})
if err != nil ...
```

## Create mail address
### With expiration
```go
addr, err := acc.CreateAddressWithExpiration(ctx)
if err != nil ...
```

### With domain and name
```go
addr, err := acc.CreateAddressWithDomainAndName(ctx, "mail4.uk", "Name")
if err != nil ...
```

If you don't set the name, pass an empty string.

#### Get available mail domains
```go
domains, err := acc.GetMailDomains(ctx)
if err != nil ...
```

### By random
```go
addr, err := acc.CreateAddressRandom(ctx)
if err != nil ...
```

## Search mail
```go
// Query is optional. If you don't set the query, API will respond with all mails.
previews, err := acc.SearchMail(ctx, addr.Address)
if err != nil ...
```

## View mail content
```go
mail, err := acc.ViewMail(ctx, previews[0])
if err != nil ...
```

## Download mail attachment
```go
attachmentBytes, err := acc.DownloadAttachment(ctx, mail.Attachments[0])
if err != nil ...
```

## Send mail
```go
file, err := os.Open("hello.txt")
if err != nil ...
defer file.Close()

res, err := acc.SendMail(ctx, instaddr.SendMailOptions{
    Files: []instaddr.UploadFileData{
        {Filename: "hello.txt", FileBody: file},
        {Filename: "hello2.txt", BufferBody: bytes.NewBuffer([]byte("Hello2"))},
    },
}, addr, "Subject", "Content", "mailto@example.com")
if err != nil ...
```

## Update mail list
```go
list, err := acc.UpdateMailAccountList(ctx)
if err != nil ...
```

## Get account's id and password
```go
info, err := acc.GetAuthInfo(ctx)
if err != nil ...
info.AccountID //01234567890
info.Password //Ex4MplE
```
