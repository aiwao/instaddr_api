package instaddr

import (
    "bytes"
    "math/rand/v2"
    "os"
    "strconv"
    "testing"
    "time"
)

func TestNewAccount(t *testing.T) {
    account, err := NewAccount(Options{})
    if err != nil {
        t.Fatal(err)
    }
    t.Log(account.CSRFToken)
    t.Log(account.CSRFSubToken)
    t.Log(account.SessionHash)
    t.Log(account.UIDencSeted)
}

func TestGetAuthInfo(t *testing.T) {
    account, err := NewAccount(Options{})
    if err != nil {
        t.Fatal(err)
    }
    info, err := account.GetAuthInfo(Options{})
    if err != nil {
        t.Fatal(err)
    }
    t.Logf("Info: [ID:%s, Password:%s]", info.AccountID, info.Password)
}

func TestGetValidMailAccountList(t *testing.T) {
    account, err := NewAccount(Options{})
    if err != nil {
        t.Fatal(err)
    }
    domains, err := account.GetMailDomains(Options{})
    if err != nil {
        t.Fatal(err)
    }
    d := "mail4.uk"
    if len(domains) > 0 {
        d = domains[rand.IntN(len(domains))]
    }
    addr, err := account.CreateAddressWithDomainAndName(OptionsWithName{Name: "Test" + strconv.Itoa(rand.IntN(1000000))}, d)
    if err != nil {
        t.Fatal(err)
    }
    t.Log("Account created: " + addr.Address)
    list, err := account.UpdateMailAccountList(Options{})
    if err != nil {
        t.Fatal(err)
    }
    t.Log("Accounts: ")
    for _, mailAcc := range list {
        t.Log(mailAcc.Address)
    }
}

func TestLoginAccount(t *testing.T) {
    acc1, err := NewAccount(Options{})
    if err != nil {
        t.Fatal(err)
    }
    t.Log("Account created: " + acc1.CSRFToken)
    addr, err := acc1.CreateAddressRandom(Options{})
    if err != nil {
        t.Fatal(err)
    }
    t.Log("Address created: " + addr.Address)
    info, err := acc1.GetAuthInfo(Options{})
    if err != nil {
        t.Fatal(err)
    }
    t.Logf("Info: [ID:%s, Password:%s]", info.AccountID, info.Password)
    list, err := acc1.UpdateMailAccountList(Options{})
    if err != nil {
        t.Fatal(err)
    }
    t.Log("Account's mail accounts: ")
    for _, mailAcc := range list {
        t.Log(mailAcc.Address)
    }

    acc2, err := LoginAccount(Options{}, info)
    if err != nil {
        t.Fatal(err)
    }
    t.Log("Logged in to account: " + acc2.CSRFToken)
    list2, err := acc2.UpdateMailAccountList(Options{})
    if err != nil {
        t.Fatal(err)
    }
    t.Log("Logged in account's mail accounts")
    for _, mailAcc := range list2 {
        t.Log(mailAcc.Address)
    }
}

func TestCreateAddressWithExpiration(t *testing.T) {
    account, err := NewAccount(Options{})
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressWithExpiration(Options{})
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
}

func TestCreateAddressWithDomainAndName(t *testing.T) {
    account, err := NewAccount(Options{})
    if err != nil {
        t.Fatal(err)
    }
    domains, err := account.GetMailDomains(Options{})
    if err != nil {
        t.Fatal(err)
    }
    domain := "mail4.uk"
    if len(domains) > 0 {
        domain = domains[0]
    }
    t.Log(domain)
    mailAcc, err := account.CreateAddressWithDomainAndName(OptionsWithName{}, domain)
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
}

func TestCreateAddressRandom(t *testing.T) {
    account, err := NewAccount(Options{})
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressRandom(Options{})
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
}

func TestSearchMail(t *testing.T) {
    account, err := NewAccount(Options{})
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressRandom(Options{})
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
    time.Sleep(60 * time.Second)
    previews, err := account.SearchMail(Options{}, mailAcc.Address)
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
    account, err := NewAccount(Options{})
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressRandom(Options{})
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
    time.Sleep(60 * time.Second)
    previews, err := account.SearchMail(Options{}, mailAcc.Address)
    if err != nil {
        t.Fatal(err)
    }
    t.Log(len(previews))
    for _, preview := range previews {
        mail, err := account.ViewMail(Options{}, preview)
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
    account, err := NewAccount(Options{})
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressRandom(Options{})
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
    time.Sleep(60 * time.Second)
    previews, err := account.SearchMail(Options{}, mailAcc.Address)
    if err != nil {
        t.Fatal(err)
    }
    t.Log(len(previews))
    for _, preview := range previews {
        mail, err := account.ViewMail(Options{}, preview)
        if err != nil {
            t.Fatal(err)
        }
        t.Log(mail.Subject)
        t.Log(mail.Content)
        for _, attachment := range mail.Attachments {
            t.Log(attachment.FileID)
            t.Log(attachment.FileKey)
            t.Log(attachment.Table)
            b, err := account.DownloadAttachment(Options{}, attachment)
            if err != nil {
                t.Log(err)
                continue
            }
            t.Log(len(b))
        }
    }
}

func TestSendMail(t *testing.T) {
    account, err := NewAccount(Options{})
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressRandom(Options{})
    if err != nil {
        t.Fatal(err)
    }
    file, err := os.Open("hello.txt")
    if err != nil {
        t.Log(err)
        return
    }
    defer file.Close()
    res, err := account.SendMail(OptionsSendMail{
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
    account, err := NewAccount(Options{})
    if err != nil {
        t.Fatal(err)
    }
    domains, err := account.GetMailDomains(Options{})
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
