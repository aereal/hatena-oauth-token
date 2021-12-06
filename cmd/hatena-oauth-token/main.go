package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/gomodule/oauth1/oauth"
)

var scopes = []string{"read_private", "read_public", "write_private", "write_public"}
var scope string

func run(argv []string) error {
	fs := flag.NewFlagSet(path.Base(argv[0]), flag.ContinueOnError)
	var (
		callbackPort int
		blogOwner    string
		blogDomain   string
	)
	fs.IntVar(&callbackPort, "port", 0, "required: callback HTTP server port")
	fs.StringVar(&blogOwner, "owner", "", "required: blog owner Hatena ID")
	fs.StringVar(&blogDomain, "domain", "", "required: blog domain")
	err := fs.Parse(argv[1:])
	if err == flag.ErrHelp {
		return nil
	}
	if err != nil {
		return err
	}
	if callbackPort == 0 {
		return fmt.Errorf("-port required")
	}
	if blogOwner == "" {
		return fmt.Errorf("blogOwner is required")
	}
	if blogDomain == "" {
		return fmt.Errorf("blogDomain is required")
	}
	cfg, err := consumeConfig("./credentials.json")
	if err != nil {
		return fmt.Errorf("consumeConfig: %w", err)
	}
	callbackURL := fmt.Sprintf("http://localhost:%d/", callbackPort)
	client := oauth.Client{
		Credentials: oauth.Credentials{
			Token:  cfg.ConsumerKey,
			Secret: cfg.ConsumerSecret,
		},
		TemporaryCredentialRequestURI: "https://www.hatena.com/oauth/initiate",
		ResourceOwnerAuthorizationURI: "https://www.hatena.ne.jp/oauth/authorize",
		TokenRequestURI:               "https://www.hatena.com/oauth/token",
	}

	tempCreds, err := client.RequestTemporaryCredentials(nil, callbackURL, url.Values{"scope": {scope}})
	if err != nil {
		return fmt.Errorf("RequestTemporaryCredentialsContext: %w", err)
	}
	authURL := client.AuthorizationURL(tempCreds, nil)
	if err := browseAuthoriationURL(authURL); err != nil {
		return err
	}
	wg := new(sync.WaitGroup)
	wg.Add(1)
	var creds *oauth.Credentials
	srv := &http.Server{
		Addr: fmt.Sprintf("localhost:%d", callbackPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				return
			}
			if token := r.URL.Query().Get("oauth_token"); token != tempCreds.Token {
				http.Error(w, "token mismatch", http.StatusInternalServerError)
				return
			}
			verifier := r.URL.Query().Get("oauth_verifier")
			if verifier == "" {
				http.Error(w, "no verifier given", http.StatusInternalServerError)
				return
			}
			creds, _, err = client.RequestToken(nil, tempCreds, verifier)
			if err != nil {
				http.Error(w, fmt.Sprintf("RequestToken(): %s", err), http.StatusInternalServerError)
				return
			}
			fmt.Fprintln(w, "auth completed")
			wg.Done()
		}),
	}
	srv.SetKeepAlivesEnabled(false)
	go func() {
		err := srv.ListenAndServe()
		if err == http.ErrServerClosed {
			log.Printf("server close")
		}
		if err != nil {
			log.Printf("! ListenAndServe(): %s", err)
		}
	}()
	wg.Wait()

	resp, err := client.Get(nil, creds, fmt.Sprintf("https://blog.hatena.ne.jp/%s/%s/atom", blogOwner, blogDomain), nil)
	if err != nil {
		return fmt.Errorf("! %w", err)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("response: status=%d body=%s", resp.StatusCode, body)
	return nil
}

type config struct {
	ConsumerKey    string
	ConsumerSecret string
}

func consumeConfig(configPath string) (*config, error) {
	f, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("os.Open: %w", err)
	}
	var ret config
	if err := json.NewDecoder(f).Decode(&ret); err != nil {
		return nil, fmt.Errorf("json.Decode: %w", err)
	}
	return &ret, nil
}

func browseAuthoriationURL(authURL string) error {
	fmt.Printf("authorization URL: %s\n", authURL)
	cmd := exec.Command("open", authURL)
	return cmd.Run()
}

func main() {
	if err := run(os.Args); err != nil {
		fmt.Printf("! %+v\n", err)
		os.Exit(1)
	}
}

func init() {
	sort.Strings(scopes)
	scope = strings.Join(scopes, ",")
}
