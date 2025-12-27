package instaddr

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "math/rand/v2"
    "mime"
    "mime/multipart"
    "net/http"
    "net/http/cookiejar"
    "net/textproto"
    "net/url"
    "os"
    "regexp"
    "strconv"
    "strings"
    "time"

    "github.com/antchfx/htmlquery"
)

const version = "4500"
const (
    baseURL       = "https://m.kuku.lu"
    indexURL      = baseURL + "/smphone.app.index.php"
    newURL        = baseURL + "/smphone.app.new.php"
    searchMailURL = baseURL + "/smphone.app.recv._ajax.php"
    viewMailURL   = baseURL + "/smphone.app.recv.view.php"
    openAttachURL = baseURL + "/smphone.app.attachopener.php"
    fileUploadURL = baseURL + "/smphone.app.new._upload.php"
    addrListURL   = baseURL + "/smphone.app.index._addrlist.php"
)
const xRequestWith = "air.kukulive.mailnow"

type Account struct {
    CSRFToken       string
    CSRFSubToken    string
    SessionHash     string
    UIDencSeted     string
    MailAccountList []MailAccount
    Jar             *cookiejar.Jar
}

type Options struct {
    Client          *http.Client
    UserAgent       string
    RandomUserAgent bool
}

func (o *Options) ua() string {
    if o.RandomUserAgent || o.UserAgent == "" {
        return randUA()
    }
    return o.UserAgent
}

func (o *Options) client() *http.Client {
    if o.Client != nil {
        return o.Client
    }
    return http.DefaultClient
}

func NewAccount(o Options) (*Account, error) {
    c := o.client()
    jar, err := cookiejar.New(nil)
    if err != nil {
        return nil, err
    }
    parse, err := url.Parse(baseURL)
    if err != nil {
        return nil, err
    }
    jar.SetCookies(parse, []*http.Cookie{{
        Name:    "cookie_timezone",
        Value:   "UTC",
        MaxAge:  63072000,
        Expires: time.Now().Add(63072000 * time.Second),
    }})
    c.Jar = jar
    //Get csrf_token
    csrf := ""
    {
        parse, err := url.Parse(newURL)
        if err != nil {
            return nil, err
        }
        q := url.Values{}
        q.Set("UID", "")
        q.Set("t", strconv.FormatInt(time.Now().Unix(), 10))
        q.Set("version", version)
        q.Set("request_unread", "1")
        parse.RawQuery = q.Encode()
        req, err := http.NewRequest("GET", parse.String(), nil)
        if err != nil {
            return nil, err
        }
        req.Header.Set("User-Agent", o.ua())
        req.Header.Set("X-Requested-With", xRequestWith)
        res, err := c.Do(req)
        if err != nil {
            return nil, err
        }
        defer res.Body.Close()
        for _, cookie := range res.Cookies() {
            if cookie.Name == "cookie_csrf_token" {
                csrf = cookie.Value
            }
        }
    }
    if csrf == "" {
        return nil, errors.New("no csrf found")
    }
    //Find new_uid
    uid := ""
    newUID := ""
    timeStr := ""
    {
        parse, err := url.Parse(indexURL)
        if err != nil {
            return nil, err
        }
        q := url.Values{}
        q.Set("UID", "")
        q.Set("t", strconv.FormatInt(time.Now().Unix(), 10))
        q.Set("version", version)
        parse.RawQuery = q.Encode()
        req, err := http.NewRequest("GET", parse.String(), nil)
        if err != nil {
            return nil, err
        }
        req.Header.Set("User-Agent", o.ua())
        req.Header.Set("X-Requested-With", xRequestWith)
        res, err := c.Do(req)
        if err != nil {
            return nil, err
        }
        defer res.Body.Close()
        b, err := io.ReadAll(res.Body)
        if err != nil {
            return nil, err
        }
        uidRegex := regexp.MustCompile(`name="UID"\s+value="([^"]+)"`)
        newUIDRegex := regexp.MustCompile(`name="MAIL_NOW_NEW_UID"\s+value="([^"]+)"`)
        timeRegex := regexp.MustCompile(`name="t"\s+value="([^"]+)"`)
        uidMatch := uidRegex.FindStringSubmatch(string(b))
        if len(uidMatch) < 2 {
            return nil, errors.New("no uid found")
        }
        uid = uidMatch[1]
        newUIDMatch := newUIDRegex.FindStringSubmatch(string(b))
        if len(newUIDMatch) < 2 {
            return nil, errors.New("no new-uid found")
        }
        newUID = newUIDMatch[1]
        timeMatch := timeRegex.FindStringSubmatch(string(b))
        if len(timeMatch) < 2 {
            return nil, errors.New("no time found")
        }
        timeStr = timeMatch[1]
    }
    if uid == "" || newUID == "" || timeStr == "" {
        return nil, errors.New("invalid response returned")
    }
    //Find session_hash and ui_denc_seted
    sessionHash := ""
    uiDencSeted := ""
    {
        parse, err := url.Parse(indexURL)
        if err != nil {
            return nil, err
        }
        form := url.Values{}
        form.Set("UID", uid)
        form.Set("MAIL_NOW_NEW_UID", newUID)
        form.Set("t", timeStr)
        req, err := http.NewRequest("POST", parse.String(), strings.NewReader(form.Encode()))
        if err != nil {
            return nil, err
        }
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req.Header.Set("User-Agent", o.ua())
        req.Header.Set("X-Requested-With", xRequestWith)
        res, err := c.Do(req)
        if err != nil {
            return nil, err
        }
        defer res.Body.Close()
        for _, cookie := range res.Cookies() {
            if cookie.Name == "cookie_sessionhash" {
                sessionHash = cookie.Value
            }
            if cookie.Name == "cookie_uidenc_seted" {
                uiDencSeted = cookie.Value
            }
        }
    }
    if sessionHash == "" || uiDencSeted == "" {
        return nil, errors.New("invalid cookie returned")
    }
    //Find csrf_subtoken
    csrfSub := ""
    {
        parse, err := url.Parse(indexURL)
        if err != nil {
            return nil, err
        }
        form := url.Values{}
        form.Set("t", strconv.FormatInt(time.Now().Unix(), 10))
        req, err := http.NewRequest("GET", parse.String(), nil)
        if err != nil {
            return nil, err
        }
        req.Header.Set("User-Agent", o.ua())
        req.Header.Set("X-Requested-With", xRequestWith)
        res, err := c.Do(req)
        if err != nil {
            return nil, err
        }
        defer res.Body.Close()
        b, err := io.ReadAll(res.Body)
        if err != nil {
            return nil, err
        }
        csrfSubRegex := regexp.MustCompile(`csrf_subtoken_check=([a-f0-9]+)`)
        csrfSubMatch := csrfSubRegex.FindStringSubmatch(string(b))
        if len(csrfSubMatch) < 2 {
            return nil, errors.New("no csrf_subtoken found")
        }
        csrfSub = csrfSubMatch[1]
    }
    if csrfSub == "" {
        return nil, errors.New("no csrf_subtoken found")
    }

    return &Account{
        CSRFToken:       csrf,
        CSRFSubToken:    csrfSub,
        SessionHash:     sessionHash,
        UIDencSeted:     uiDencSeted,
        MailAccountList: []MailAccount{},
        Jar:             jar,
    }, nil
}

type AuthInfo struct {
    AccountID string
    Password  string
}

func LoginAccount(o Options, authInfo AuthInfo) (*Account, error) {
    acc, err := NewAccount(o)
    if err != nil {
        return nil, err
    }
    c := o.client()
    c.Jar = acc.Jar

    parse, err := url.Parse(indexURL)
    if err != nil {
        return nil, err
    }
    form := url.Values{}
    form.Set("action", "checkLogin")
    form.Set("confirmcode", "")
    form.Set("nopost", "1")
    form.Set("csrf_token_check", acc.CSRFToken)
    form.Set("csrf_subtoken_check", acc.CSRFSubToken)
    form.Set("number", authInfo.AccountID)
    form.Set("password", authInfo.Password)
    form.Set("syncconfirm", "")
    {
        req, err := http.NewRequest("POST", parse.String(), strings.NewReader(form.Encode()))
        if err != nil {
            return nil, err
        }
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        req.Header.Set("User-Agent", o.ua())
        req.Header.Set("X-Requested-With", xRequestWith)
        res, err := c.Do(req)
        if err != nil {
            return nil, err
        }
        defer res.Body.Close()
    }
    {
        form.Set("syncconfirm", "yes")
        req, err := http.NewRequest("POST", parse.String(), strings.NewReader(form.Encode()))
        if err != nil {
            return nil, err
        }
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        req.Header.Set("User-Agent", o.ua())
        req.Header.Set("X-Requested-With", xRequestWith)
        res, err := c.Do(req)
        if err != nil {
            return nil, err
        }
        defer res.Body.Close()
        b, err := io.ReadAll(res.Body)
        if err != nil {
            return nil, err
        }
        if !strings.Contains(strings.ToLower(string(b)), "shash") {
            return nil, errors.New("failed to login")
        }
        shash := strings.ReplaceAll(string(b), "OK:", "")
        acc.SessionHash = shash
        parseBase, err := url.Parse(baseURL)
        if err != nil {
            return nil, err
        }
        cookies := []*http.Cookie{}
        for _, cookie := range acc.Jar.Cookies(parseBase) {
            if cookie.Name == "cookie_sessionhash" {
                cookie.Value = url.QueryEscape(shash)
            }
            cookies = append(cookies, cookie)
        }
        acc.Jar.SetCookies(parseBase, cookies)
    }
    return acc, nil
}

func (a *Account) GetAuthInfo(o Options) (AuthInfo, error) {
    c := o.client()
    c.Jar = a.Jar
    parse, err := url.Parse(indexURL)
    info := AuthInfo{}
    if err != nil {
        return info, err
    }
    q := url.Values{}
    q.Set("passcodelock", "off")
    q.Set("t", strconv.FormatInt(time.Now().Unix(), 10))
    q.Set("pagemode_login", "1")
    q.Set("noindex", "1")
    q.Set("version", version)
    parse.RawQuery = q.Encode()
    req, err := http.NewRequest("GET", parse.String(), nil)
    if err != nil {
        return info, err
    }
    req.Header.Set("User-Agent", o.ua())
    req.Header.Set("X-Requested-With", xRequestWith)
    res, err := c.Do(req)
    if err != nil {
        return info, err
    }
    defer res.Body.Close()
    b, err := io.ReadAll(res.Body)
    if err != nil {
        return info, err
    }
    doc, err := htmlquery.Parse(strings.NewReader(string(b)))
    if err != nil {
        return info, err
    }
    accountIDNode := htmlquery.FindOne(doc, `//*[@id="area_numberview"]`)
    if accountIDNode == nil {
        return info, errors.New("failed to get accountID")
    }
    info.AccountID = htmlquery.InnerText(accountIDNode)

    passwordNode := htmlquery.FindOne(doc, `//*[@id="area_passwordview_copy"]`)
    if passwordNode == nil {
        return info, errors.New("failed to get password")
    }
    info.Password = htmlquery.InnerText(passwordNode)
    return info, nil
}

type MailAccount struct {
    Address string
}

func (a *Account) UpdateMailAccountList(o Options) ([]MailAccount, error) {
    c := o.client()
    c.Jar = a.Jar
    parse, err := url.Parse(addrListURL)
    list := []MailAccount{}
    if err != nil {
        return nil, err
    }
    q := url.Values{}
    currentTime := time.Now().Unix()
    q.Set("t", strconv.FormatInt(currentTime, 10))
    q.Set("nopost", "1")
    q.Set("_", strconv.FormatInt(currentTime-rand.Int64N(1000), 10))
    parse.RawQuery = q.Encode()
    req, err := http.NewRequest("GET", parse.String(), nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("User-Agent", o.ua())
    req.Header.Set("X-Requested-With", xRequestWith)
    res, err := c.Do(req)
    if err != nil {
        return nil, err
    }
    defer res.Body.Close()
    b, err := io.ReadAll(res.Body)
    if err != nil {
        return nil, err
    }
    emailRegex := regexp.MustCompile(`openMailAddrData\(\s*"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})"\s*\)`)
    emailMatches := emailRegex.FindAllStringSubmatch(string(b), -1)
    for _, m := range emailMatches {
        if len(m) > 1 {
            list = append(list, MailAccount{Address: m[1]})
        }
    }
    a.MailAccountList = list
    return list, nil
}

func (a *Account) CreateAddressWithExpiration(o Options) (MailAccount, error) {
    c := o.client()
    c.Jar = a.Jar
    parse, err := url.Parse(indexURL)
    if err != nil {
        return MailAccount{}, err
    }
    q := url.Values{}
    q.Set("action", "addMailAddrByOnetime")
    q.Set("nopost", "1")
    q.Set("by_system", "1")
    q.Set("csrf_token_check", a.CSRFToken)
    q.Set("csrf_subtoken_check", a.CSRFSubToken)
    q.Set("recaptcha_token", "")
    q.Set("_", strconv.FormatInt(time.Now().Unix(), 10))
    parse.RawQuery = q.Encode()
    req, err := http.NewRequest("GET", parse.String(), nil)
    if err != nil {
        return MailAccount{}, err
    }
    req.Header.Set("User-Agent", o.ua())
    req.Header.Set("X-Requested-With", xRequestWith)
    res, err := c.Do(req)
    if err != nil {
        return MailAccount{}, err
    }
    defer res.Body.Close()
    b, err := io.ReadAll(res.Body)
    if err != nil {
        return MailAccount{}, err
    }
    addrRegex := regexp.MustCompile(`([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)
    addrMatch := addrRegex.FindStringSubmatch(string(b))
    if len(addrMatch) < 2 {
        return MailAccount{}, errors.New("failed to create address")
    }

    mailAcc := MailAccount{
        Address: addrMatch[1],
    }
    a.MailAccountList = append(a.MailAccountList, mailAcc)
    return mailAcc, nil
}

type OptionsWithName struct {
    Name string
    Options
}

func (a *Account) CreateAddressWithDomainAndName(o OptionsWithName, domain string) (MailAccount, error) {
    c := o.client()
    c.Jar = a.Jar
    var prevTime int64
    {
        parse, err := url.Parse(indexURL)
        if err != nil {
            return MailAccount{}, err
        }
        q := url.Values{}
        q.Set("action", "checkNewMailUser")
        q.Set("nopost", "1")
        q.Set("by_system", "1")
        q.Set("csrf_token_check", a.CSRFToken)
        q.Set("csrf_subtoken_check", a.CSRFSubToken)
        q.Set("newdomain", domain)
        q.Set("newuser", o.Name)
        prevTime = time.Now().Unix()
        q.Set("_", strconv.FormatInt(prevTime, 10))
        parse.RawQuery = q.Encode()
        req, err := http.NewRequest("GET", parse.String(), nil)
        if err != nil {
            return MailAccount{}, err
        }
        req.Header.Set("User-Agent", o.ua())
        req.Header.Set("X-Requested-With", xRequestWith)
        res, err := c.Do(req)
        if err != nil {
            return MailAccount{}, err
        }
        defer res.Body.Close()
    }
    //Add mail and find address from response
    parse, err := url.Parse(indexURL)
    if err != nil {
        return MailAccount{}, err
    }
    q := url.Values{}
    q.Set("action", "addMailAddrByManual")
    q.Set("nopost", "1")
    q.Set("by_system", "1")
    q.Set("t", strconv.FormatInt(time.Now().Unix(), 10))
    q.Set("csrf_token_check", a.CSRFToken)
    q.Set("csrf_subtoken_check", a.CSRFSubToken)
    q.Set("newdomain", domain)
    q.Set("newuser", o.Name)
    q.Set("recaptcha_token", "")
    q.Set("_", strconv.FormatInt(prevTime+1, 10))
    parse.RawQuery = q.Encode()
    req, err := http.NewRequest("GET", parse.String(), nil)
    if err != nil {
        return MailAccount{}, err
    }
    req.Header.Set("User-Agent", o.ua())
    req.Header.Set("X-Requested-With", xRequestWith)
    res, err := c.Do(req)
    if err != nil {
        return MailAccount{}, err
    }
    defer res.Body.Close()
    b, err := io.ReadAll(res.Body)
    if err != nil {
        return MailAccount{}, err
    }
    addrRegex := regexp.MustCompile(`([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)
    addrMatch := addrRegex.FindStringSubmatch(string(b))
    if len(addrMatch) < 2 {
        return MailAccount{}, errors.New("failed to create address")
    }

    mailAcc := MailAccount{
        Address: addrMatch[1],
    }
    a.MailAccountList = append(a.MailAccountList, mailAcc)
    return mailAcc, nil
}

func (a *Account) CreateAddressRandom(o Options) (MailAccount, error) {
    c := o.client()
    c.Jar = a.Jar
    //Add mail and find address from response
    parse, err := url.Parse(indexURL)
    if err != nil {
        return MailAccount{}, err
    }
    q := url.Values{}
    q.Set("action", "addMailAddrByAuto")
    q.Set("nopost", "1")
    q.Set("by_system", "1")
    q.Set("csrf_token_check", a.CSRFToken)
    q.Set("csrf_subtoken_check", a.CSRFSubToken)
    q.Set("recaptcha_token", "")
    q.Set("_", strconv.FormatInt(time.Now().Unix(), 10))
    parse.RawQuery = q.Encode()
    req, err := http.NewRequest("GET", parse.String(), nil)
    if err != nil {
        return MailAccount{}, err
    }
    req.Header.Set("User-Agent", o.ua())
    req.Header.Set("X-Requested-With", xRequestWith)
    res, err := c.Do(req)
    if err != nil {
        return MailAccount{}, err
    }
    defer res.Body.Close()
    b, err := io.ReadAll(res.Body)
    if err != nil {
        return MailAccount{}, err
    }
    addrRegex := regexp.MustCompile(`([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)
    addrMatch := addrRegex.FindStringSubmatch(string(b))
    if len(addrMatch) < 2 {
        return MailAccount{}, errors.New("failed to create address")
    }

    mailAcc := MailAccount{
        Address: addrMatch[1],
    }
    a.MailAccountList = append(a.MailAccountList, mailAcc)
    return mailAcc, nil
}

type MailPreview struct {
    MailID  string
    Subject string
    From    string
    To      string
    ViewKey string
}

func (a *Account) SearchMail(o Options, searchQuery string) ([]MailPreview, error) {
    c := o.client()
    c.Jar = a.Jar
    parse, err := url.Parse(searchMailURL)
    if err != nil {
        return nil, err
    }
    q := url.Values{}
    q.Set("q", searchQuery)
    q.Set("nopost", "1")
    q.Set("csrf_token_check", a.CSRFToken)
    q.Set("csrf_subtoken_check", a.CSRFSubToken)
    q.Set("_", strconv.FormatInt(time.Now().Unix(), 10))
    parse.RawQuery = q.Encode()
    req, err := http.NewRequest("GET", parse.String(), nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("User-Agent", o.ua())
    req.Header.Set("X-Requested-With", xRequestWith)
    res, err := c.Do(req)
    if err != nil {
        return nil, err
    }
    defer res.Body.Close()
    b, err := io.ReadAll(res.Body)
    if err != nil {
        return nil, err
    }
    doc, err := htmlquery.Parse(strings.NewReader(string(b)))
    if err != nil {
        return nil, err
    }
    mailNumRegex := regexp.MustCompile(`mailnumlist\s*=\s*"([^"]+)"`)
    mailNumMatch := mailNumRegex.FindStringSubmatch(string(b))
    if len(mailNumMatch) < 2 {
        return nil, errors.New("no mail_num_list found")
    }
    mailNumList := strings.Split(strings.ReplaceAll(mailNumMatch[1], " ", ""), ",")
    if len(mailNumList) == 0 {
        return nil, errors.New("no mails found")
    }
    mailPreviewList := []MailPreview{}
    for _, mailNum := range mailNumList {
        preview := MailPreview{}
        preview.MailID = mailNum
        mailTitleNode := htmlquery.FindOne(doc, fmt.Sprintf("//*[@id='area_mail_title_%s']/b/span", mailNum))
        if mailTitleNode != nil {
            preview.Subject = htmlquery.InnerText(mailTitleNode)
        }
        fromNode := htmlquery.FindOne(doc, fmt.Sprintf("//*[@id='link_maildata_%s']/div[3]/div/div[1]", mailNum))
        if fromNode != nil {
            preview.From = htmlquery.InnerText(fromNode)
        }
        toNode := htmlquery.FindOne(doc, fmt.Sprintf("//*[@id='link_maildata_%s']/div[3]/div/div[2]", mailNum))
        if toNode != nil {
            preview.To = htmlquery.InnerText(toNode)
        }
        viewKeyRegex := regexp.MustCompile(fmt.Sprintf(`openMailData\('%s', '([a-f0-9]+)'`, mailNum))
        viewKeyMatch := viewKeyRegex.FindStringSubmatch(string(b))
        if len(viewKeyMatch) > 1 {
            preview.ViewKey = viewKeyMatch[1]
        }
        mailPreviewList = append(mailPreviewList, preview)
    }
    return mailPreviewList, nil
}

type Attachment struct {
    FileID  string
    FileKey string
    Table   string
}

type Mail struct {
    Subject     string
    Content     string
    Attachments []Attachment
}

func (a *Account) ViewMail(o Options, mailPreview MailPreview) (*Mail, error) {
    c := o.client()
    c.Jar = a.Jar
    parse, err := url.Parse(viewMailURL)
    if err != nil {
        return nil, err
    }
    form := url.Values{}
    form.Set("num", mailPreview.MailID)
    form.Set("key", mailPreview.ViewKey)
    form.Set("noscroll", "1")
    req, err := http.NewRequest("POST", parse.String(), strings.NewReader(form.Encode()))
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Set("User-Agent", o.ua())
    req.Header.Set("X-Requested-With", xRequestWith)
    res, err := c.Do(req)
    if err != nil {
        return nil, err
    }
    defer res.Body.Close()
    b, err := io.ReadAll(res.Body)
    if err != nil {
        return nil, err
    }
    doc, err := htmlquery.Parse(strings.NewReader(string(b)))
    if err != nil {
        return nil, err
    }
    mail := &Mail{Subject: mailPreview.Subject}
    contentNode := htmlquery.FindOne(doc, "//*[@id='area-data']")
    if contentNode != nil {
        mail.Content = htmlquery.InnerText(contentNode)
    }
    attachOpenerRegex := regexp.MustCompile(`(smphone\.app\.attachopener\.php[^"]*)`)
    attachOpenerMatches := attachOpenerRegex.FindAllStringSubmatch(string(b), -1)
    attachments := []Attachment{}
    for _, match := range attachOpenerMatches {
        if len(match) < 2 {
            continue
        }
        src := match[1]
        if strings.Contains(strings.ToLower(src), "smphone.app.attachopener.php") {
            attach := Attachment{}
            parsedAttachURL, err := url.Parse("https://" + src)
            if err != nil {
                continue
            }
            queries := parsedAttachURL.Query()
            attach.FileID = queries.Get("num")
            attach.FileKey = queries.Get("filekey")
            attach.Table = queries.Get("table")
            attachments = append(attachments, attach)
        }
    }
    mail.Attachments = attachments
    return mail, nil
}

func (a *Account) DownloadAttachment(o Options, attachment Attachment) ([]byte, error) {
    c := o.client()
    c.Jar = a.Jar
    parse, err := url.Parse(openAttachURL)
    if err != nil {
        return nil, err
    }
    q := url.Values{}
    q.Set("type", "attach_recv")
    q.Set("table", attachment.Table)
    q.Set("num", attachment.FileID)
    q.Set("filekey", attachment.FileKey)
    q.Set("share_id", "")
    parse.RawQuery = q.Encode()
    req, err := http.NewRequest("GET", parse.String(), nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("User-Agent", o.ua())
    req.Header.Set("X-Requested-With", xRequestWith)
    res, err := c.Do(req)
    if err != nil {
        return nil, err
    }
    defer res.Body.Close()
    b, err := io.ReadAll(res.Body)
    if err != nil {
        return nil, err
    }
    return b, nil
}

type UploadFileData struct {
    Filename   string
    FileBody   *os.File
    BufferBody *bytes.Buffer
    ReaderBody *bytes.Reader
    FileType   string
}

type SendMailResponse struct {
    Result string `json:"result"`
    Msg    string `json:"msg"`
}

type OptionsSendMail struct {
    Files []UploadFileData
    Options
}

type fileUploadInfo struct {
    filename string
    fileType string
    size     int64
    buffer   io.Reader
}

func (a *Account) SendMail(o OptionsSendMail, mailAccount MailAccount, subject, content, to string) (*SendMailResponse, error) {
    c := o.client()
    c.Jar = a.Jar

    //Get hash and uuid
    hash := ""
    uuid := ""
    startTime := time.Now()
    {
        parse, err := url.Parse(newURL)
        if err != nil {
            return nil, err
        }
        q := url.Values{}
        q.Set("passcodelock", "off")
        q.Set("t", strconv.FormatInt(startTime.Unix(), 10))
        q.Set("version", version)
        parse.RawQuery = q.Encode()
        req, err := http.NewRequest("GET", parse.String(), nil)
        if err != nil {
            return nil, err
        }
        req.Header.Set("User-Agent", o.ua())
        req.Header.Set("X-Requested-With", xRequestWith)
        res, err := c.Do(req)
        if err != nil {
            return nil, err
        }
        defer res.Body.Close()
        b, err := io.ReadAll(res.Body)
        if err != nil {
            return nil, err
        }
        tempHashRegex := regexp.MustCompile(`name="sendtemp_hash"\s+value="([^"]+)"`)
        tempHashMatch := tempHashRegex.FindStringSubmatch(string(b))
        tempHash := ""
        if len(tempHashMatch) > 1 {
            tempHash = tempHashMatch[1]
        }

        fileHashRegex := regexp.MustCompile(`name="file_hash"\s+value="([^"]+)"`)
        fileHashMatch := fileHashRegex.FindStringSubmatch(string(b))
        fileHash := ""
        if len(fileHashMatch) > 1 {
            fileHash = fileHashMatch[1]
        }

        if tempHash == "" && fileHash == "" {
            return nil, errors.New("no hashes found")
        }
        if tempHash != "" {
            hash = tempHash
        } else {
            hash = fileHash
        }
        uuidRegex := regexp.MustCompile(`fd\.append\("uuid",\s*"([a-fA-F0-9]+)"\)`)
        uuidMatch := uuidRegex.FindStringSubmatch(string(b))
        if len(uuidMatch) < 2 {
            return nil, errors.New("no uuid found")
        }
        uuid = uuidMatch[1]
    }
    if uuid == "" {
        return nil, errors.New("no uuid found")
    }

    if len(o.Files) > 0 {
        totalSize := int64(0)
        payloadPrepare := "{"
        var infoList []fileUploadInfo
        for i, file := range o.Files {
            fileSize := int64(-1)
            var fileBody io.Reader = nil
            if file.FileBody != nil {
                fileBody = file.FileBody
                stat, err := file.FileBody.Stat()
                if err != nil {
                    continue
                }
                fileSize = stat.Size()
            } else if file.BufferBody != nil {
                fileBody = file.BufferBody
                fileSize = int64(file.BufferBody.Len())
            } else if file.ReaderBody != nil {
                fileBody = file.ReaderBody
                fileSize = file.ReaderBody.Size()
            }
            if fileSize == -1 || fileBody == nil {
                continue
            }
            infoList = append(infoList, fileUploadInfo{filename: file.Filename, size: fileSize, buffer: fileBody})
            totalSize += fileSize
            lastStr := ","
            if len(o.Files)-1 == i {
                lastStr = "}"
            }
            payloadPrepare += fmt.Sprintf(`"%d":{"filename":"%s","size":%d}%s`, i, file.Filename, fileSize, lastStr)
        }
        if len(infoList) > 0 {
            //Register file hash
            {
                parse, err := url.Parse(newURL)
                if err != nil {
                    return nil, err
                }
                form := url.Values{}
                form.Set("action", "registFileHashToken")
                form.Set("nopost", "1")
                form.Set("file_hash", hash)
                form.Set("csrf_token_check", a.CSRFToken)
                form.Set("t", strconv.FormatInt(time.Now().Unix(), 10))
                req, err := http.NewRequest("POST", parse.String(), strings.NewReader(form.Encode()))
                if err != nil {
                    return nil, err
                }
                req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
                req.Header.Set("User-Agent", o.ua())
                req.Header.Set("X-Requested-With", xRequestWith)
                res, err := c.Do(req)
                if err != nil {
                    return nil, err
                }
                res.Body.Close()
            }
            //Prepare upload
            {
                parse, err := url.Parse(fileUploadURL)
                if err != nil {
                    return nil, err
                }
                form := url.Values{}
                form.Set("action", "prepareUpload2")
                form.Set("file_hash", hash)
                form.Set("totalcount", strconv.Itoa(len(infoList)))
                form.Set("totalsize", strconv.FormatInt(totalSize, 10))
                form.Set("upload_files", payloadPrepare)
                req, err := http.NewRequest("POST", parse.String(), strings.NewReader(form.Encode()))
                if err != nil {
                    return nil, err
                }
                req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
                req.Header.Set("User-Agent", o.ua())
                req.Header.Set("X-Requested-With", xRequestWith)
                res, err := c.Do(req)
                if err != nil {
                    return nil, err
                }
                res.Body.Close()
            }
            //Upload file
            for _, info := range infoList {
                b := &bytes.Buffer{}
                mw := multipart.NewWriter(b)
                mw.SetBoundary(webkitBoundary())
                mw.WriteField("action", "uploadFile2")
                mw.WriteField("service", "MailNow")
                mw.WriteField("ajax", "1")
                mw.WriteField("ajax_back", "1")
                mw.WriteField("file_hash", hash)
                mw.WriteField("filecnt", "1")
                mw.WriteField("uuid", uuid)
                mw.WriteField("file_1_name", info.filename)
                mw.WriteField("file_1_size", strconv.FormatInt(info.size, 10))

                fileType := "text/plain"
                if info.fileType != "" {
                    fileType = info.fileType
                } else {
                    ext := ""
                    split := strings.Split(info.filename, ".")
                    if len(split) > 0 {
                        ext = split[len(split)-1]
                    }
                    if ext != "" {
                        tempType := mime.TypeByExtension("." + ext)
                        if tempType != "" {
                            fileType = tempType
                        }
                    }
                }
                mw.WriteField("file_1_type", fileType)

                h := make(textproto.MIMEHeader)
                h.Set("Content-Disposition", `form-data; name="file_1"; filename="`+info.filename+`"`)
                h.Set("Content-Type", fileType)
                part, _ := mw.CreatePart(h)
                io.Copy(part, info.buffer)

                mw.Close()

                parse, err := url.Parse(fileUploadURL)
                if err != nil {
                    return nil, err
                }
                req, err := http.NewRequest("POST", parse.String(), b)
                if err != nil {
                    return nil, err
                }
                req.Header.Set("Content-Type", mw.FormDataContentType())
                req.Header.Set("User-Agent", o.ua())
                req.Header.Set("X-Requested-With", xRequestWith)
                res, err := c.Do(req)
                if err != nil {
                    return nil, err
                }
                res.Body.Close()
            }
        }
    }
    //Send
    var sendMailRes SendMailResponse
    {
        parse, err := url.Parse(newURL)
        if err != nil {
            return nil, err
        }
        form := url.Values{}
        form.Set("action", "sendMail")
        form.Set("ajax", "1")
        form.Set("csrf_token_check", a.CSRFToken)
        form.Set("sendmail_replymode", "")
        form.Set("sendmail_replynum", "")
        form.Set("sendtemp_hash", hash)
        form.Set("sendmail_from", mailAccount.Address)
        form.Set("sendmail_to", to)
        form.Set("sendmail_subject", subject)
        form.Set("sendmail_content", content)
        form.Set("sendmail_content_add", "")
        form.Set("file_hash", hash)
        req, err := http.NewRequest("POST", parse.String(), strings.NewReader(form.Encode()))
        if err != nil {
            return nil, err
        }
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        req.Header.Set("User-Agent", o.ua())
        req.Header.Set("X-Requested-With", xRequestWith)
        res, err := c.Do(req)
        if err != nil {
            return nil, err
        }
        defer res.Body.Close()
        b, err := io.ReadAll(res.Body)
        if err != nil {
            return nil, err
        }
        err = json.Unmarshal(b, &sendMailRes)
        if err != nil {
            return nil, err
        }
    }
    return &sendMailRes, nil
}

func (a *Account) GetMailDomains(o Options) ([]string, error) {
    domains := []string{}
    c := o.client()
    c.Jar = a.Jar
    parse, err := url.Parse(indexURL)
    if err != nil {
        return nil, err
    }
    q := url.Values{}
    q.Set("UID", "")
    q.Set("t", strconv.FormatInt(time.Now().Unix(), 10))
    q.Set("version", version)
    q.Set("request_unread", "1")
    parse.RawQuery = q.Encode()
    req, err := http.NewRequest("GET", parse.String(), nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("User-Agent", o.ua())
    req.Header.Set("X-Requested-With", xRequestWith)
    res, err := c.Do(req)
    if err != nil {
        return nil, err
    }
    defer res.Body.Close()
    b, err := io.ReadAll(res.Body)
    if err != nil {
        return nil, err
    }

    doc, err := htmlquery.Parse(strings.NewReader(string(b)))
    if err != nil {
        return nil, err
    }
    nodes := htmlquery.Find(doc, `//*input[@type="radio", @name="input_manualmaildomain"]`)
    for _, n := range nodes {
        if v := htmlquery.SelectAttr(n, "value"); v != "" && strings.Contains(v, ".") {
            domains = append(domains, v)
        }
    }
    return domains, nil
}
