package instaddr

import (
    "testing"
    "time"
)

func TestNewAccount(t *testing.T) {
    account, err := NewAccount(nil)
    if err != nil {
        t.Fatal(err)
    }
    t.Log(account.CSRFToken)
    t.Log(account.CSRFSubToken)
    t.Log(account.SessionHash)
    t.Log(account.UIDencSeted)
}

func TestCreateAddressWithExpiration(t *testing.T) {
    account, err := NewAccount(nil)
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressWithExpiration(nil)
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
}

func TestCreateAddressWithDomainAndName(t *testing.T) {
    account, err := NewAccount(nil)
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressWithDomainAndName(nil, "mail4.uk", "")
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
}

func TestCreateAddressRandom(t *testing.T) {
    account, err := NewAccount(nil)
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressRandom(nil)
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
}

func TestSearchMail(t *testing.T) {
    account, err := NewAccount(nil)
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressRandom(nil)
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
    time.Sleep(60 * time.Second)
    previews, err := account.SearchMail(nil, mailAcc.Address)
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
    account, err := NewAccount(nil)
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressRandom(nil)
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
    time.Sleep(60 * time.Second)
    previews, err := account.SearchMail(nil, mailAcc.Address)
    if err != nil {
        t.Fatal(err)
    }
    t.Log(len(previews))
    for _, preview := range previews {
        mail, err := account.ViewMail(nil, preview)
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
    account, err := NewAccount(nil)
    if err != nil {
        t.Fatal(err)
    }
    mailAcc, err := account.CreateAddressRandom(nil)
    if err != nil {
        t.Fatal(err)
    }
    t.Log(mailAcc.Address)
    time.Sleep(60 * time.Second)
    previews, err := account.SearchMail(nil, mailAcc.Address)
    if err != nil {
        t.Fatal(err)
    }
    t.Log(len(previews))
    for _, preview := range previews {
        mail, err := account.ViewMail(nil, preview)
        if err != nil {
            t.Fatal(err)
        }
        t.Log(mail.Subject)
        t.Log(mail.Content)
        for _, attachment := range mail.Attachments {
            t.Log(attachment.FileID)
            t.Log(attachment.FileKey)
            t.Log(attachment.Table)
            b, err := account.DownloadAttachment(nil, attachment)
            if err != nil {
                t.Log(err)
                continue
            }
            t.Log(len(b))
        }
    }
}

func TestUA(t *testing.T) {
    for i := 0; i < 10; i++ {
        t.Log(ua())
    }
}
