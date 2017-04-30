// SWAT - Swift Auth Token
// A wrapper to getting swift auth token
// Copyright (c) 2016 Stuart Glenn
// All rights reserved
// Use of this source code is goverened by a BSD 3-clause license,
// see included LICENSE file for details
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/codegangsta/cli"
	"github.com/howeyc/gopass"
)

const (
	TENANT_PREFIX = "LDAP_"
)

type AuthResponse struct {
	Access struct {
		Token struct {
			Expires string
			Id      string
			Tenant  struct {
				Id   string
				Name string
			}
		}
		User struct {
			Id    string
			Name  string
			Roles []struct {
				Description string
				Id          string
				Name        string
				TenantId    string
			}
		}
		ServiceCatalog []struct {
			Name      string
			Type      string
			Endpoints []struct {
				Region    string
				PublicUrl string
				TenantId  string
			}
		}
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "swat"
	app.Usage = "Swift Auth Token Getter/Saver"
	app.Version = "0.2.1 - 20170430"
	app.Author = "Stuart Glenn"
	app.Email = "Stuart-Glenn@omrf.org"
	app.Copyright = "2017 Stuart Glenn, All rights reserved"

	current_user, err := user.Current()
	default_username := ""
	if nil == err {
		default_username = current_user.Username
	}

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "V, verbose",
			Usage: "show more output",
		},
		cli.StringFlag{
			Name:   "auth-url, a",
			Usage:  "Swift auth url endpoint",
			EnvVar: "OS_AUTH_URL",
		},
	}

	app.Commands = []cli.Command{
		cli.Command{
			Name:        "login",
			Usage:       "Login to swift and obtain AUTH_TOKEN",
			ArgsUsage:   "[--persist=false] [--tenant ACCOUNT]",
			Description: "Send swift login and optionally persist auth token",
			Flags: []cli.Flag{
				cli.BoolTFlag{
					Name:  "persist, p",
					Usage: "persist AUTH_TOKEN to filesystem, defaults to true",
				},
				cli.StringFlag{
					Name:  "tenant, t",
					Usage: fmt.Sprintf("swift account/tenant to access, defaults to username with prefix %s", TENANT_PREFIX),
				},
				cli.StringFlag{
					Name:  "username, u",
					Usage: "swift username for authentication, default to current user",
					Value: default_username,
				},
			},
			Action: generateToken,
		},
		cli.Command{
			Name:        "tenants",
			Usage:       "List avaiable tenants/accounts",
			ArgsUsage:   "",
			Description: "Login to get list of knonwn allowed tenants for user in swift",
			Action:      listTenants,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "username, u",
					Usage: "swift username for authentication, default to current user",
					Value: default_username,
				},
			},
		},
	}
	app.RunAndExitOnError()
}

func login(c *cli.Context) (*AuthResponse, error) {
	auth_url := c.GlobalString("auth-url")
	if "" == auth_url {
		fmt.Fprintf(os.Stderr, "Missing auth url endpoint\n")
		cli.ShowSubcommandHelp(c)
		os.Exit(1)
	}
	account := c.String("tenant")
	a, err := postLogin(auth_url, account, "", "")
	if nil == err {
		return a, err
	}

	username := c.String("username")
	if "" == account {
		account = fmt.Sprintf("%s%s", TENANT_PREFIX, username)
	}
	fmt.Fprintf(os.Stderr, "%s/%s password: ", username, account)
	password, err := gopass.GetPasswd()
	if nil != err {
		fmt.Fprintf(os.Stderr, "Failure getting password: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "\n")
	return postLogin(auth_url, account, username, string(password))
}

func generateToken(c *cli.Context) {
	a, err := login(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	account := c.String("tenant")
	publicUrl := a.Access.ServiceCatalog[0].Endpoints[0].PublicUrl
	for _, e := range a.Access.ServiceCatalog[0].Endpoints {
		if e.TenantId == account {
			publicUrl = e.PublicUrl
			break
		}
	}

	env := []string{
		"unset OS_AUTH_TOKEN OS_STORAGE_URL",
		fmt.Sprintf("export OS_AUTH_TOKEN='%s'", a.Access.Token.Id),
		fmt.Sprintf("export OS_STORAGE_URL='%s'", publicUrl),
	}
	fmt.Println(strings.Join(env, ";"))
	if c.BoolT("persist") {
		fh, _ := os.OpenFile(filepath.Join(os.Getenv("HOME"), ".swiftrc"),
			os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
			os.FileMode(0600))
		defer fh.Close()
		w := bufio.NewWriter(fh)
		fmt.Fprintln(w, strings.Join(env, "\n"))
		fmt.Fprintf(w, "#Expires %s", a.Access.Token.Expires)
		w.Flush()
	}
}

func listTenants(c *cli.Context) {
	a, err := login(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
	r, _ := regexp.Compile(`\A(` + TENANT_PREFIX + `ss[-_](?:prj[-_])?.*)([-_]readers)\z`)
	for _, e := range a.Access.ServiceCatalog[0].Endpoints {
		fmt.Println(r.ReplaceAllString(e.TenantId, "$1"))
	}
}

func postLogin(url, tenant, username, password string) (*AuthResponse, error) {
	var j []byte
	if "" == username && "" == password {
		j = []byte(fmt.Sprintf(`{"auth": {"tenantName": "%s","token": {"id": "%s"}}}`, tenant, os.Getenv("OS_AUTH_TOKEN")))
	} else {
		j = []byte(fmt.Sprintf(`{"auth": {"tenantName": "%s","passwordCredentials": {"username": "%s","password": "%s"}}}`, tenant, username, password))
	}
	body := bytes.NewBuffer(j)

	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest("POST", url, body)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}
	if http.StatusUnauthorized == resp.StatusCode {
		return nil, errors.New("Unauthorized")
	} else if http.StatusOK != resp.StatusCode {
		return nil, errors.New(fmt.Sprintf("Unknown response: %d", resp.StatusCode))
	}

	respBody, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	a := &AuthResponse{}
	err = json.Unmarshal([]byte(respBody), a)
	return a, err
}
