package instaddr

import (
    "bytes"
    "context"
    "io"
    "math/rand/v2"
    "net/http"
    "net/http/cookiejar"
    "os"
    "strconv"
    "strings"
    "testing"
    "time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
    return f(req)
}

type contextKey string

func TestClientContext(t *testing.T) {
    jar, err := cookiejar.New(nil)
    if err != nil {
        t.Fatal(err)
    }

    key := contextKey("request-id")
    ctx := context.WithValue(context.Background(), key, "ctx-value")
    sawContext := false
    client := &http.Client{
        Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
            if got := req.Context().Value(key); got != "ctx-value" {
                t.Fatalf("request context value = %v, want ctx-value", got)
            }
            sawContext = true
            body := `<div id="area_numberview">account-id</div><div id="area_passwordview_copy">password</div>`
            return &http.Response{
                StatusCode: http.StatusOK,
                Header:     make(http.Header),
                Body:       io.NopCloser(strings.NewReader(body)),
                Request:    req,
            }, nil
        }),
    }
    apiClient := NewClient(ClientOptions{HTTPClient: client})
    account := &Account{Jar: jar, client: apiClient}

    info, err := account.GetAuthInfo(ctx)
    if err != nil {
        t.Fatal(err)
    }
    if !sawContext {
        t.Fatal("transport was not called")
    }
    if info.AccountID != "account-id" || info.Password != "password" {
        t.Fatalf("auth info = %#v", info)
    }
}

func TestNewAccount(t *testing.T) {
    account, err := NewAccount(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    t.Log(account.CSRFToken)
    t.Log(account.CSRFSubToken)
    t.Log(account.SessionHash)
    t.Log(account.UIDencSeted)
}

func TestGetAuthInfo(t *testing.T) {
    account, err := NewAccount(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    info, err := account.GetAuthInfo(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    t.Logf("Info: [ID:%s, Password:%s]", info.AccountID, info.Password)
}

func TestUpdateMailAccountList(t *testing.T) {
    account, err := NewAccount(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    domains, err := account.GetMailDomains(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    d := "mail4.uk"
    if len(domains) > 0 {
        d = domains[rand.IntN(len(domains))]
    }
    addr, err := account.CreateAddressWithDomainAndName(context.Background(), d, "Test"+strconv.Itoa(rand.IntN(1000000)))
    if err != nil {
        t.Fatal(err)
    }
    t.Log("Account created: " + addr.Address)
    list, err := account.UpdateMailAccountList(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    t.Log("Accounts: ")
    for _, mailAcc := range list {
        t.Log(mailAcc.Address)
    }
}

func TestLoginAccount(t *testing.T) {
    acc1, err := NewAccount(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    t.Log("Account created: " + acc1.CSRFToken)
    addr, err := acc1.CreateAddressRandom(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    t.Log("Address created: " + addr.Address)
    info, err := acc1.GetAuthInfo(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    t.Logf("Info: [ID:%s, Password:%s]", info.AccountID, info.Password)
    list, err := acc1.UpdateMailAccountList(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    t.Log("Account's mail accounts: ")
    for _, mailAcc := range list {
        t.Log(mailAcc.Address)
    }

    acc2, err := LoginAccount(context.Background(), info)
    if err != nil {
        t.Fatal(err)
    }
    t.Log("Logged in to account: " + acc2.CSRFToken)
    list2, err := acc2.UpdateMailAccountList(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    t.Log("Logged in account's mail accounts")
    for _, mailAcc := range list2 {
        t.Log(mailAcc.Address)
    }
}

func TestCreateAddressWithExpiration(t *testing.T) {
    account, err := NewAccount(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressWithExpiration(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
}

func TestCreateAddressWithDomainAndName(t *testing.T) {
    account, err := NewAccount(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    domains, err := account.GetMailDomains(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    domain := "mail4.uk"
    if len(domains) > 0 {
        domain = domains[0]
    }
    t.Log(domain)
    mailAcc, err := account.CreateAddressWithDomainAndName(context.Background(), domain, "")
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
}

func TestCreateAddressRandom(t *testing.T) {
    account, err := NewAccount(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressRandom(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
}

func TestSearchMail(t *testing.T) {
    account, err := NewAccount(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressRandom(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
    time.Sleep(60 * time.Second)
    previews, err := account.SearchMail(context.Background(), mailAcc.Address)
    if err != nil {
        t.Fatal(err)
    }
    t.Log(len(previews))
    for _, preview := range previews {
        t.Log(preview.Subject)
        t.Log(preview.From)
        t.Log(preview.To)
    }
}

func TestViewMail(t *testing.T) {
    account, err := NewAccount(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressRandom(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
    time.Sleep(60 * time.Second)
    previews, err := account.SearchMail(context.Background(), mailAcc.Address)
    if err != nil {
        t.Fatal(err)
    }
    t.Log(len(previews))
    for _, preview := range previews {
        mail, err := account.ViewMail(context.Background(), preview)
        if err != nil {
            t.Fatal(err)
        }
        t.Log(mail.Subject)
        t.Log(mail.Content)
        for _, attachment := range mail.Attachments {
            t.Log(attachment.FileID)
            t.Log(attachment.FileKey)
            t.Log(attachment.Table)
        }
    }
}

func TestDownloadAttachment(t *testing.T) {
    account, err := NewAccount(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressRandom(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
    time.Sleep(60 * time.Second)
    previews, err := account.SearchMail(context.Background(), mailAcc.Address)
    if err != nil {
        t.Fatal(err)
    }
    t.Log(len(previews))
    for _, preview := range previews {
        mail, err := account.ViewMail(context.Background(), preview)
        if err != nil {
            t.Fatal(err)
        }
        t.Log(mail.Subject)
        t.Log(mail.Content)
        for _, attachment := range mail.Attachments {
            t.Log(attachment.FileID)
            t.Log(attachment.FileKey)
            t.Log(attachment.Table)
            b, err := account.DownloadAttachment(context.Background(), attachment)
            if err != nil {
                t.Log(err)
                continue
            }
            t.Log(len(b))
        }
    }
}

func TestSendMail(t *testing.T) {
    account, err := NewAccount(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressRandom(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    file, err := os.Open("hello.txt")
    if err != nil {
        t.Log(err)
        return
    }
    defer file.Close()
    res, err := account.SendMail(context.Background(), SendMailOptions{
        Files: []UploadFileData{
            {Filename: "hello.txt", FileBody: file},
            {Filename: "hello2.txt", BufferBody: bytes.NewBuffer([]byte("Hello2"))},
        },
    }, mailAcc, "Hello", "Konichiwa", "yobimefa@heisei.be")
    if err != nil {
        t.Fatal(err)
    }
    t.Log(res.Result)
}

func TestGetMailDomains(t *testing.T) {
    account, err := NewAccount(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    domains, err := account.GetMailDomains(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    t.Log(len(domains))
    for _, domain := range domains {
        t.Log(domain)
    }
}

func TestUA(t *testing.T) {
    for i := 0; i < 10; i++ {
        t.Log(randUA())
    }
}

func TestWebkitBoundary(t *testing.T) {
    for i := 0; i < 10; i++ {
        t.Log(webkitBoundary())
    }
}
