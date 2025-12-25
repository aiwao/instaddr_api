package instaddr

import (
    "os"
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
    res, err := account.SendMail(OptionsSendMail{Files: []UploadFileData{{Filename: "hello.txt", FileBody: file}}}, mailAcc, "Hello", "Konichiwa", "yobimefa@heisei.be")
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
