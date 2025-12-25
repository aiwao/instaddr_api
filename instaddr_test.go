package instaddr

import (
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
    mailAcc, err := account.CreateAddressWithDomainAndName(Options{}, "mail4.uk", "")
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
    res, err := account.SendMail(OptionsSendMail{}, mailAcc, "Hello", "Konichiwa", "zebyo749@f5.si")
    if err != nil {
        t.Fatal(err)
    }
    t.Log(res.Result)
}

func TestUA(t *testing.T) {
    for i := 0; i < 10; i++ {
        t.Log(randUA())
    }
}
