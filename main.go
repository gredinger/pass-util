package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"golang.org/x/text/encoding/unicode"
	ldap "gopkg.in/ldap.v2"
	yaml "gopkg.in/yaml.v2"
)

//DomainInfo is the configuration for the domain
type DomainInfo struct {
	Domain          string `yaml:"domain"`
	User            string `yaml:"bind_username"`
	Password        string `yaml:"bind_password"`
	SearchPath      string `yaml:"search_cn"`
	PrivilegedGroup string `yaml:"reset_priv_group"`
	TargetGroup     string `yaml:"reset_user_group"`
	SelfReset       bool   `yaml:"self_reset"`
	SMTPServer      string `yaml:"smtp_server"`
	From            string `yaml:"from"`
	Log             string `yaml:"log_file"`
}

func print(o string) {
	f, err := os.OpenFile(di.Log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	tp := time.Now().Format("2006-01-02T15:04:05.999999-07:00")
	o = fmt.Sprintf("%s: %s\r\n", tp, o)
	if _, err = f.WriteString(o); err != nil {
		log.Fatal(err)
	}
}

// HTTP server and handler
func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/reset", resetHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/forgot", forgotHandler)
	serv := http.ListenAndServe("0.0.0.0:80", nil)
	log.Fatal(serv)
}

var di DomainInfo

func forgotHandler(rw http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("forgot.tmpl")
	if err != nil {
		print("Unable to parse forgot.tmpl")
	}
	if r.FormValue("email") != "" && r.FormValue("username") != "" {
		err := sendToken(r.FormValue("email"), r.FormValue("username"))
		if err != nil {
			print(fmt.Sprintf("%s: %s has failed to send a reset email with the following error \r\n%s\r\n", r.RemoteAddr, r.FormValue("username"), err.Error()))
			t.Execute(rw, err)
		} else {
			print(fmt.Sprintf("%s: %s has requested an email reset", r.RemoteAddr, r.FormValue("username")))
			t.Execute(rw, "Please check your email for the reset message")
		}

	} else if r.FormValue("token") != "" {
		abuser, err, user := validateToken(r.FormValue("token"))
		if err != nil {
			t.Execute(rw, "Unable to find token")
		}
		if abuser {
			t.Execute(rw, "Abuser has been reported and may be blacklisted")
		}
		if !abuser && err == nil {
			ses := addSession(user)
			cookie := authCookie(ses)
			http.SetCookie(rw, &cookie)
			http.Redirect(rw, r, "/reset", 302)
		}
	} else {
		t.Execute(rw, nil)
	}
}

//validateToken
// Returns bool - is Naughty Token
// Returns error - if unvalidated
func validateToken(token string) (bool, error, string) {
	if token == "" {
		return false, errors.New("No token defined"), ""
	}
	for i, x := range tokens {
		if time.Now().After(x.ExpirationDate) {
			tokens = append(tokens[:i], tokens[i+1:]...)
		} else if strings.EqualFold(x.Token, token) {
			tokens = append(tokens[:i], tokens[i+1:]...)
			return false, nil, x.Username
		} else if strings.EqualFold(x.AbuseToken, token) {
			tokens = append(tokens[:i], tokens[i+1:]...)
			return true, nil, ""
		}
	}
	return false, errors.New("Invalid session"), ""
}

func sendToken(email, username string) error {
	di := getDomainInfo()
	sr := searchUsername(username, "mail", "givenName")
	res, err := searchLDAP(sr)
	if err != nil {
		return err
	}
	mail := res[0].GetAttributeValue("mail")
	print(fmt.Sprintf("Reset email sent to %s", mail))
	if strings.EqualFold(email, mail) {
		t, err := template.ParseFiles("email.tmpl")
		if err != nil {
			return err
		}
		c, err := smtp.Dial(di.SMTPServer)
		if err != nil {
			return err
		}
		c.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err := c.Mail(di.From); err != nil {
			log.Fatal(err)
		}
		if err := c.Rcpt(mail); err != nil {
			log.Fatal(err)
		}
		buf, err := c.Data()

		token := Token{
			FirstName:      res[0].GetAttributeValue("givenName"),
			Token:          randSeq(64),
			AbuseToken:     randSeq(64),
			Mail:           mail,
			Username:       username,
			ExpirationDate: time.Now().Add(time.Hour * 24),
		}
		t.Execute(buf, token)
		tokens = append(tokens, token)
		defer c.Quit()
		return buf.Close()

	} else {
		return errors.New("Email does not match username")
	}
}

type Token struct {
	FirstName      string
	Token          string
	AbuseToken     string
	Mail           string
	Username       string
	ExpirationDate time.Time
}

func searchLDAP(sr *ldap.SearchRequest) ([]*ldap.Entry, error) {
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", di.Domain, 389))
	if err != nil {
		return nil, err
	}
	defer l.Close()
	err = l.Bind(di.User, di.Password)
	if err != nil {
		return nil, err
	}
	res, err := l.Search(sr)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) < 1 {
		return nil, errors.New("No user found with that username")
	}

	return res.Entries, nil
}

// List of sessions for memory
var sessions = make([]Session, 0)

// List of tokens in memory
var tokens = make([]Token, 0)

//Session is a user session
type Session struct {
	Username       string
	SessionID      string
	ExpirationDate time.Time
}

//addSessions appends the session to list of sessions
func addSession(username string) Session {
	uid := randSeq(128)
	ses := Session{
		Username:       username,
		SessionID:      uid,
		ExpirationDate: time.Now().Add(24 * time.Hour * 30), // 24 hours in a day, 30 days in a month
	}
	sessions = append(sessions, ses)
	return ses
}

//validateSession verfies that the session exists in the list of sessions
func validateSession(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	for i, s := range sessions {
		if time.Now().After(s.ExpirationDate) { // remove sessions that have expired
			sessions = append(sessions[:i], sessions[i+1:]...)
		}
		if sessionID == s.SessionID {
			return true
		}
	}
	return false
}

func removeSession(sessionID string) bool {
	for i, s := range sessions {
		if sessionID == s.SessionID {
			sessions = append(sessions[:i], sessions[i+1:]...)
			return true
		}
	}
	return false
}

//getSession returns session information from the SessionID
func getSession(sessionID string) Session {
	for _, s := range sessions {
		if sessionID == s.SessionID {
			return s
		}
	}
	return Session{}
}

func init() {
	rand.Seed(time.Now().UnixNano())
	di = getDomainInfo()
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func authCookie(ses Session) http.Cookie {
	cookie := http.Cookie{
		Name:    "Auth",
		Value:   ses.SessionID,
		Expires: ses.ExpirationDate,
	}
	return cookie
}

func searchUsername(username string, attributes ...string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		di.SearchPath,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(sAMAccountName=%s))", username),
		append(attributes, "dn"),
		nil,
	)
}

func newSecureBind() *ldap.Conn {
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", di.Domain, 389))
	if err != nil {
		print(err.Error())
		return nil
	}
	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		print(err.Error())
		return nil
	}
	err = l.Bind(di.User, di.Password)
	if err != nil {
		print(err.Error())
		return nil
	}
	return l
}

func isPrivedUser(username string) bool {
	l := newSecureBind()
	defer l.Close()
	sea := searchUsername(username, "memberOf")
	res, err := l.Search(sea)
	if err != nil {
		return false
	}
	if len(res.Entries) > 1 || len(res.Entries) < 1 {
		return false
	}
	for _, s := range res.Entries[0].GetAttributeValues("memberOf") {
		if strings.EqualFold(s, di.PrivilegedGroup) {
			return true
		}
	}
	return false
}

func isTargetUser(username string) bool {
	l := newSecureBind()
	defer l.Close()
	sea := searchUsername(username, "memberOf")
	res, err := l.Search(sea)
	if err != nil {
		return false
	}

	if len(res.Entries) > 1 || len(res.Entries) < 1 {
		return false
	}
	for _, s := range res.Entries[0].GetAttributeValues("memberOf") {
		if strings.EqualFold(s, di.TargetGroup) {
			return true
		}
	}
	return false
}

func resetPassword(username, password string, ses Session) error {
	l := newSecureBind()
	defer l.Close()
	sea := searchUsername(username, "memberOf")
	res, err := l.Search(sea)
	if err != nil {
		return err
	}
	if len(res.Entries) < 1 {
		return errors.New("No user found with that username")
	}

	inGroup := false
	resetSelf := false
	for _, s := range res.Entries[0].GetAttributeValues("memberOf") {
		if strings.EqualFold(s, di.TargetGroup) {
			inGroup = true
		}
	}
	if di.SelfReset {
		if strings.EqualFold(username, ses.Username) {
			resetSelf = true
		}
	}
	if di.SelfReset {
		if inGroup {

		} else if !resetSelf {
			return errors.New("You are not authorized to reset this user's password")
		}
	} else { //selfReset = false, so only check if is in group
		if !inGroup {
			return errors.New("You are not authorized to reset this user's password")
		}
	}
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)

	encoded, err := utf16.NewEncoder().String(fmt.Sprintf("\"%s\"", password))
	if err != nil {
		return err
	}

	modify := ldap.NewModifyRequest(res.Entries[0].DN)

	modify.Replace("unicodePwd", []string{encoded})

	return l.Modify(modify)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("Auth")
	if err != nil {
		print(err.Error())
	}
	removeSession(cookie.Value)
	c := &http.Cookie{
		Name:    "Auth",
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),
	}
	http.SetCookie(w, c)
	http.Redirect(w, r, "/login", 302)
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("Auth")
	if err != nil {
		http.Redirect(w, r, "/login", 302)
		return
	}
	if validateSession(cookie.Value) {
		ses := getSession(cookie.Value)
		err := r.ParseForm()
		t, _ := template.ParseFiles("reset.tmpl")
		if err != nil {
			print(err.Error())
		}
		if r.FormValue("username") != "" && r.FormValue("password") != "" {
			err := resetPassword(r.FormValue("username"), r.FormValue("password"), ses)
			if err != nil {
				print(fmt.Sprintf("%s: %s has failed to reset %s's password with the following error\r\n%s\r\n", r.RemoteAddr, ses.Username, r.FormValue("username"), err.Error()))
				t.Execute(w, err)
			} else {
				print(fmt.Sprintf("%s: %s has successfully reset %s's password", r.RemoteAddr, ses.Username, r.FormValue("username")))
				t.Execute(w, "Password has been reset successfully")
			}
		} else {
			t.Execute(w, nil)
		}
	} else {
		http.Redirect(w, r, "/login", 302)
	}

}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// need to check if user is actually valid. First we need to query AD for that information.
	err := r.ParseForm()
	if err != nil {
		print(err.Error())
	}
	t, _ := template.ParseFiles("login.tmpl")
	if r.FormValue("username") != "" && r.FormValue("password") != "" {
		err := authenticateUser(r.FormValue("username"), r.FormValue("password"))
		if err != nil {
			print(fmt.Sprintf("%s: %s has failed to auth correctly", r.RemoteAddr, r.FormValue("username")))
			t.Execute(w, err)
		} else {
			print(fmt.Sprintf("%s: %s has successfully logged in.", r.RemoteAddr, r.FormValue("username")))
			ses := addSession(r.FormValue("username"))
			cookie := authCookie(ses)
			http.SetCookie(w, &cookie)
		}
		http.Redirect(w, r, "/reset", 302)
	} else {
		t.Execute(w, nil)
	}

}

//authenicate user verifies the username/password combination is valid
func authenticateUser(username, password string) error {
	l := newSecureBind()
	defer l.Close()
	if l == nil {
		return errors.New("Unable to connect to server")
	}
	sea := searchUsername(username, "memberOf")
	res, err := l.Search(sea)
	if err != nil {
		return err
	}
	if len(res.Entries) < 1 {
		return errors.New("No user found with that username")
	}

	userdn := res.Entries[0].DN
	err = l.Bind(userdn, password)
	if err != nil {
		return err
	}
	return nil
}

//getDomainInfo loads the settings from config.yml
func getDomainInfo() DomainInfo {
	di := DomainInfo{}

	f, err := os.Open("config.yml")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fi, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(fi, &di)
	if err != nil {
		panic(err)
	}
	return di
}

//homeHandler checks if user is authenticated
//if the user is authenticated it will redirect them to the reset page
//if the user is not authenticated, it will redirect them to the login page
func homeHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("Auth")
	if err != nil {
		http.Redirect(w, r, "/login", 302)
		return
	}
	if err != nil {
		http.Redirect(w, r, "/login", 302)
	}
	if validateSession(cookie.Value) {
		http.Redirect(w, r, "/reset", 302)
	} else {
		http.Redirect(w, r, "/login", 302)
	}
	w.WriteHeader(404)
	w.Write([]byte("Somehow, you broke our site..."))
}
