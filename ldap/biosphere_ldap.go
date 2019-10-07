package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	ldap "gopkg.in/ldap.v3"
	yaml "gopkg.in/yaml.v2"

	terraConfig "github.com/osallou/goterra-lib/lib/config"
	terraModel "github.com/osallou/goterra-lib/lib/model"
	terraUser "github.com/osallou/goterra-lib/lib/user"
)

// LdapConfig defines ldap connection parameters
type LdapConfig struct {
	Host          string
	Port          uint64
	AdminCN       string `yaml:"admin_cn"`
	AdminPassword string `yaml:"admin_password"`
	DN            string `yaml:"dn"`
	OU            string `yaml:"ou"`
	GID           int    `yaml:"gid"`
	MinUID        int64  `yaml:"minuid"`
	TLS           bool   `yaml:"tls"`
}

// UserConfig defines user creation
type UserConfig struct {
	Home   string
	Ldap   LdapConfig
	APIKey string `yaml:"apikey"`
}

// BiosphereConfig is the yaml config for biosphere
type BiosphereConfig struct {
	Users  UserConfig
	Loaded bool
}

var biosphereConfig BiosphereConfig

//LoadConfig loads biosphere.yml or file from GOT_BIOSPHERE_CONFIG env var
func LoadConfig() BiosphereConfig {
	if biosphereConfig.Loaded {
		return biosphereConfig
	}
	cfgFile := "biosphere.yml"
	if os.Getenv("GOT_BIOSPHERE_LDAP_CONFIG") != "" {
		cfgFile = os.Getenv("GOT_BIOSPHERE_LDAP_CONFIG")
	}

	cfg, _ := ioutil.ReadFile(cfgFile)
	yaml.Unmarshal([]byte(cfg), &biosphereConfig)
	if os.Getenv("GOT_BIOSPHERE_LDAP_HOST") != "" {
		biosphereConfig.Users.Ldap.Host = os.Getenv("GOT_BIOSPHERE_LDAP_HOST")
	}
	if os.Getenv("GOT_BIOSPHERE_LDAP_PORT") != "" {
		port, err := strconv.ParseInt(os.Getenv("GOT_BIOSPHERE_LDAP_PORT"), 10, 64)
		if err == nil {
			biosphereConfig.Users.Ldap.Port = uint64(port)
		}
	}
	if os.Getenv("GOT_BIOSPHERE_LDAP_ADMIN_CN") != "" {
		biosphereConfig.Users.Ldap.AdminCN = os.Getenv("GOT_BIOSPHERE_LDAP_ADMIN_CN")
	}
	if os.Getenv("GOT_BIOSPHERE_LDAP_ADMIN_PASSWORD") != "" {
		biosphereConfig.Users.Ldap.AdminPassword = os.Getenv("GOT_BIOSPHERE_LDAP_ADMIN_PASSWORD")
	}
	if os.Getenv("GOT_BIOSPHERE_LDAP_DN") != "" {
		biosphereConfig.Users.Ldap.DN = os.Getenv("GOT_BIOSPHERE_LDAP_DN")
	}
	if os.Getenv("GOT_BIOSPHERE_LDAP_OU") != "" {
		biosphereConfig.Users.Ldap.OU = os.Getenv("GOT_BIOSPHERE_LDAP_OU")
	}
	if os.Getenv("GOT_BIOSPHERE_LDAP_GID") != "" {
		val, err := strconv.ParseInt(os.Getenv("GOT_BIOSPHERE_LDAP_GID"), 10, 64)
		if err == nil {
			biosphereConfig.Users.Ldap.GID = int(val)
		}
	}
	if os.Getenv("GOT_BIOSPHERE_LDAP_MIDUID") != "" {
		val, err := strconv.ParseInt(os.Getenv("GOT_BIOSPHERE_LDAP_MINUID"), 10, 64)
		if err == nil {
			biosphereConfig.Users.Ldap.MinUID = val
		}
	}
	if os.Getenv("GOT_BIOSPHERE_LDAP_TLS") == "1" {
		biosphereConfig.Users.Ldap.TLS = true
	}
	if os.Getenv("GOT_BIOSPHERE_HOME") != "" {
		biosphereConfig.Users.Home = os.Getenv("GOT_BIOSPHERE_HOME")
	}
	if os.Getenv("GOT_BIOSPHERE_APIKEY") != "" {
		biosphereConfig.Users.APIKey = os.Getenv("GOT_BIOSPHERE_APIKEY")
	}

	return biosphereConfig
}

// OnUserUpdate creates user in ldap if necessary and adds ssh key
func OnUserUpdate(action terraModel.UserAction, uidNumber int64) {
	var user terraUser.User
	err := json.Unmarshal([]byte(action.Data), &user)
	if err != nil {
		log.Error().Msgf("Failed to decode user: %s", action.Data)
		return
	}
	if user.SSHPubKey == "" {
		log.Debug().Msg("User has no ssh key declared")
		return
	}
	config := LoadConfig()
	if config.Users.Ldap.Host == "" {
		log.Warn().Msg("No LDAP settings, skipping")
		return
	}

	userHome := fmt.Sprintf(config.Users.Home, user.UID)

	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", config.Users.Ldap.Host, config.Users.Ldap.Port))
	if err != nil {
		log.Error().Msgf("ldap conn error: %s", err)
		return
	}
	defer l.Close()

	if config.Users.Ldap.TLS {
		// Reconnect with TLS
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			log.Error().Msgf("ldap tls error: %s", err)
			return
		}
	}

	// First bind with a read only user
	err = l.Bind(config.Users.Ldap.AdminCN, config.Users.Ldap.AdminPassword)
	if err != nil {
		log.Error().Msgf("ldap bind error: %s", err)
		return
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		fmt.Sprintf("ou=%s,%s", config.Users.Ldap.OU, config.Users.Ldap.DN),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(uid=%s))", user.UID),
		[]string{"dn", "uidNumber"},
		nil,
	)

	UID := uidNumber + biosphereConfig.Users.Ldap.MinUID
	sr, err := l.Search(searchRequest)
	if err != nil || len(sr.Entries) == 0 {
		log.Info().Msgf("ldap user not found, creating it: %s => %d", user.UID, UID)
		log.Debug().Msgf("New entry %s", fmt.Sprintf("uid=%s,ou=%s,%s", user.UID, config.Users.Ldap.OU, config.Users.Ldap.DN))
		req := ldap.NewAddRequest(fmt.Sprintf("uid=%s,ou=%s,%s", user.UID, config.Users.Ldap.OU, config.Users.Ldap.DN), nil)
		req.Attribute("homeDirectory", []string{userHome})
		req.Attribute("cn", []string{user.Email})
		req.Attribute("sn", []string{user.UID})
		req.Attribute("gidNumber", []string{fmt.Sprintf("%d", config.Users.Ldap.GID)})
		req.Attribute("uidNumber", []string{fmt.Sprintf("%d", UID)})
		req.Attribute("loginShell", []string{"/bin/bash"})
		req.Attribute("objectClass", []string{"PosixAccount", "inetOrgPerson"})
		err = l.Add(req)
		if err != nil {
			log.Error().Msgf("Failed to add user in ldap: %s", err)
			return
		}
	} else {
		log.Debug().Msgf("Got user in ldap: %s => %d", user.UID, UID)
		for _, attr := range sr.Entries[0].Attributes {
			log.Debug().Msgf("%s => %s", attr.Name, attr.Values[0])
			if attr.Name == "uidNumber" {
				var UIDErr error
				UID, UIDErr = strconv.ParseInt(attr.Values[0], 10, 64)
				if UIDErr != nil {
					log.Error().Msgf("invalid uidnumber: %+v", attr.Values)
					return
				}
				break
			}
		}
	}

	userSSHPath := fmt.Sprintf("%s/.ssh", userHome)
	_, homeErr := os.Stat(userSSHPath)
	if os.IsNotExist(homeErr) {
		os.MkdirAll(userHome, 0755)
		os.Mkdir(userSSHPath, 0700)
	}

	userAuthorizedKeys := fmt.Sprintf("%s/authorized_keys", userSSHPath)
	ioutil.WriteFile(userAuthorizedKeys, []byte(user.SSHPubKey), 0644)
	var chErr error
	if os.IsNotExist(homeErr) {
		chErr = os.Chown(userHome, int(UID), config.Users.Ldap.GID)
		if chErr != nil {
			log.Error().Msgf("Failed to chown %s", userHome)
		}
		chErr = os.Chown(userSSHPath, int(UID), config.Users.Ldap.GID)
		if chErr != nil {
			log.Error().Msgf("Failed to chown %s", userSSHPath)
		}
	}
	chErr = os.Chown(userAuthorizedKeys, int(UID), config.Users.Ldap.GID)
	if chErr != nil {
		log.Error().Msgf("Failed to chown %s", userAuthorizedKeys)
	}

}

// Version defines current software version
var Version string

// HomeHandler manages base entrypoint
var HomeHandler = func(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{"version": Version, "message": "ok"}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// CheckToken checks Fernet token
func CheckToken(apikey string) error {
	config := LoadConfig()

	if apikey != config.Users.APIKey {
		return fmt.Errorf("invliad api key")
	}
	return nil
}

// UserDefaultHandler add user in ldap if necessary and updates ssh key in his home directory
var UserDefaultHandler = func(w http.ResponseWriter, r *http.Request) {
	err := CheckToken(r.Header.Get("X-API-KEY"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid apikey"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	data := &terraUser.User{}
	err = json.NewDecoder(r.Body).Decode(data)
	userJSON, _ := json.Marshal(data)
	action := terraModel.UserAction{
		UID:    data.UID,
		Action: "user_update",
		Data:   string(userJSON),
	}
	vars := mux.Vars(r)
	userUIDNumber, errUID := strconv.ParseInt(vars["uidNumber"], 10, 64)
	if errUID != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid uidNumber"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	OnUserUpdate(action, userUIDNumber)
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if os.Getenv("GOT_DEBUG") != "" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	config := terraConfig.LoadConfig()

	r := mux.NewRouter()
	r.HandleFunc("/biosphere-ldap", HomeHandler).Methods("GET")
	r.HandleFunc("/biosphere-ldap/user/{id}/{uidNumber}", UserDefaultHandler).Methods("POST")

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowedHeaders:   []string{"Authorization"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
	})
	handler := c.Handler(r)

	loggedRouter := handlers.LoggingHandler(os.Stdout, handler)

	srv := &http.Server{
		Handler: loggedRouter,
		Addr:    fmt.Sprintf("%s:%d", config.Web.Listen, config.Web.Port),
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	srv.ListenAndServe()

}
