package main

/*

TODO
* on create_user, create user on endpoints and endpoint secrets

* on create_ns
 * create project if not exists for selected endpoint (project = ns) and per_ns_project = true
 * add user role to project
 * add endpoint defaults
* on update_ns
 * add user role to project (if needed to create project)

* for genouest, query all users at regular interval, get their pubkey and create/update them locally
*/

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	terraUtils "github.com/osallou/goterra-auth/lib/utils"
	terraConfig "github.com/osallou/goterra-lib/lib/config"
	terraModel "github.com/osallou/goterra-lib/lib/model"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	yaml "gopkg.in/yaml.v2"
)

// Endpoint defined base config for an endpoint
type Endpoint struct {
	ID                 string `yaml:"id"`
	Name               string `yaml:"name"`
	User               string `yaml:"user"`
	Password           string `yaml:"password"`
	DomainID           string `yaml:"domain"`
	ProjectID          string `yaml:"project"`
	KeystoneURL        string `yaml:"keystone"`
	NovaURL            string `yaml:"nova"`
	DefaultProjectID   string `yaml:"project_id_default"`
	DefaultProjectName string `yaml:"project_name_default"`
	PerNSProject       bool   `yaml:"per_ns_project"`
	KeypairDefault     string `yaml:"keypair_default"`
	UserRole           string `yaml:"user_role"`
}

// BiosphereConfig is the yaml config for biosphere
type BiosphereConfig struct {
	Endpoints []Endpoint
}

var biosphereConfig BiosphereConfig

func endpointDefaultsExists(uid string, endpoint Endpoint, ns string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	filter := bson.M{
		"ui":        uid,
		"endpoint":  endpoint.ID,
		"namespace": ns,
	}

	var epd terraModel.EndpointDefaults
	err := endpointDefaultsCollection.FindOne(ctx, filter).Decode(&epd)
	if err != nil {
		return false
	}
	return true
}

func userExists(token string, uid string, endpoint Endpoint) (*BiosphereUser, error) {
	// config := terraConfig.LoadConfig()
	// biosphereCollection := mongoClient.Database(config.Mongo.DB).Collection("user_ep_defaults")

	// biosphereUserCollection := mongoClient.Database(config.Mongo.DB).Collection("biosphere_users")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	userdb := BiosphereUser{}
	filter := bson.M{
		"uid":      uid,
		"endpoint": endpoint.ID,
	}
	err := biosphereUserCollection.FindOne(ctx, filter).Decode(&userdb)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}
	return &userdb, nil
}

func projectExists(token string, ns string, endpoint Endpoint) (*BiosphereNS, error) {
	// config := terraConfig.LoadConfig()
	// biosphereCollection := mongoClient.Database(config.Mongo.DB).Collection("user_ep_defaults")

	// biosphereNSCollection := mongoClient.Database(config.Mongo.DB).Collection("biosphere_ns")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nsdb := BiosphereNS{}
	filter := bson.M{
		"id":       ns,
		"endpoint": endpoint.ID,
	}
	err := biosphereNSCollection.FindOne(ctx, filter).Decode(&nsdb)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}
	return &nsdb, nil
}

//LoadConfig loads biosphere.yml or file from GOT_BIOSPHERE_CONFIG env var
func LoadConfig() BiosphereConfig {
	cfgFile := "biosphere.yml"
	if os.Getenv("GOT_BIOSPHERE_CONFIG") != "" {
		cfgFile = os.Getenv("GOT_BIOSPHERE_CONFIG")
	}

	cfg, _ := ioutil.ReadFile(cfgFile)
	yaml.Unmarshal([]byte(cfg), &biosphereConfig)
	return biosphereConfig
}

type openstackIdentityDef struct {
	Methods  []string                     `json:"methods"`
	Password map[string]map[string]string `json:"password"`
}

type openstackAuthDef struct {
	Identity openstackIdentityDef              `json:"identity"`
	Scope    map[string]map[string]interface{} `json:"scope"`
}

type openstackAuthReqDef struct {
	Auth openstackAuthDef `json:"auth"`
}

type openstackProjectInfoDef struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Domain      string `json:"domain_id"`
	Enabled     bool   `json:"enabled"`
	IsDomain    bool   `json:"is_domain"`
}

type openstackProjectDef struct {
	Project openstackProjectInfoDef `json:"project"`
}

type openstackUserDef struct {
	User map[string]interface{} `json:"user"`
}

func createUserEndpointDefaults(uid string, endpoint Endpoint, userID string, projectID string, projectName string, ns string) error {
	if endpointDefaultsExists(uid, endpoint, ns) {
		return nil
	}
	defaults := make(map[string][]string)
	defaults["user_id"] = []string{userID}
	defaults["project_id"] = []string{projectID}
	defaults["project_name"] = []string{projectName}
	defaults["keypair"] = []string{endpoint.KeypairDefault}
	newUserDefaults := terraModel.EndpointDefaults{
		UID:       uid,
		Endpoint:  endpoint.ID,
		Defaults:  defaults,
		Namespace: ns,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := endpointDefaultsCollection.InsertOne(ctx, newUserDefaults)
	if err != nil {
		return fmt.Errorf("%s", err)
	}
	return nil

}

type biosphereProjectDef struct {
	Name string
	ID   string
}

// OnUserCreate creates a user on all endpoints
func OnUserCreate(action terraModel.UserAction) {
	cfg := LoadConfig()
	if action.Data != "aai" {
		return
	}
	token, tokenErr := GetToken(cfg.Endpoints[0], cfg.Endpoints[0].DefaultProjectID)
	if tokenErr != nil {
		log.Error().Msgf("Auth failed: %s", tokenErr)
		return
	}
	createUserOnEndpoints(token, action.UID, cfg.Endpoints)
}

func getNSMembers(nsID string) []string {
	config := terraConfig.LoadConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	objID, _ := primitive.ObjectIDFromHex(nsID)
	ns := bson.M{
		"_id": objID,
	}

	var nsdb terraModel.NSData
	nSCollection := mongoClient.Database(config.Mongo.DB).Collection("ns")
	err := nSCollection.FindOne(ctx, ns).Decode(&nsdb)
	if err != nil {
		return make([]string, 0)
	}

	members := append(nsdb.Owners, nsdb.Members...)
	return members
}

// OnNSCreate creates a project and adds user to project on openstack and update all endpoint defaults
func OnNSCreate(action terraModel.UserAction) {
	cfg := LoadConfig()

	token, tokenErr := GetToken(cfg.Endpoints[0], cfg.Endpoints[0].DefaultProjectID)
	if tokenErr != nil {
		log.Error().Msgf("Auth failed: %s", tokenErr)
		return
	}
	createProjectOnEndpoints(token, action.Data, action.UID, cfg.Endpoints)
	members := getNSMembers(action.Data)
	for _, member := range members {
		addUserToProjectOnEndpoints(token, action.Data, member, cfg.Endpoints)
		createUserEndpointDefaultsOnEndpoints(member, action.Data, cfg.Endpoints)
	}
}

// OnNSUpdate adds user to a project on openstack and update all endpoint defaults
func OnNSUpdate(action terraModel.UserAction) {
	cfg := LoadConfig()

	token, tokenErr := GetToken(cfg.Endpoints[0], cfg.Endpoints[0].DefaultProjectID)
	if tokenErr != nil {
		log.Error().Msgf("Auth failed: %s", tokenErr)
		return
	}

	members := getNSMembers(action.Data)
	for _, member := range members {
		addUserToProjectOnEndpoints(token, action.Data, member, cfg.Endpoints)
		createUserEndpointDefaultsOnEndpoints(member, action.Data, cfg.Endpoints)
	}

}

func createUserEndpointDefaultsOnEndpoints(uid string, ns string, endpoints []Endpoint) {
	for _, endpoint := range endpoints {
		if _, ok := Users[uid]; !ok {
			continue
		}
		if _, ok := Namespaces[ns]; !ok {
			continue
		}
		userID, uok := Users[uid][endpoint.ID]
		projectID, pok := Namespaces[ns][endpoint.ID]
		if !uok || !pok {
			continue
		}
		projectName := endpoint.DefaultProjectName
		if endpoint.PerNSProject {
			projectName = ns
		}
		createUserEndpointDefaults(uid, endpoint, userID, projectID, projectName, ns)
	}
}

func addUserToProjectOnEndpoints(token string, ns string, uid string, endpoints []Endpoint) {
	for _, endpoint := range endpoints {
		if _, ok := Users[uid]; !ok {
			continue
		}
		if _, ok := Namespaces[ns]; !ok {
			continue
		}
		userID, uok := Users[uid][endpoint.ID]
		projectID, pok := Namespaces[ns][endpoint.ID]
		if !uok || !pok {
			continue
		}
		err := addUserToProject(token, endpoint, projectID, userID)
		if err != nil {
			log.Error().Str("endpoint", endpoint.ID).Str("ns", ns).Str("user", uid).Msg("Failed to add user to project on endpoint")
		}

	}
}

func addUserToProject(token string, endpoint Endpoint, projectID string, userID string) error {
	request, err := http.NewRequest("PUT", fmt.Sprintf("%s/v3/projects/%s/users/%s/roles/%s", endpoint.KeystoneURL, projectID, userID, endpoint.UserRole), nil)
	request.Header.Set("Content-type", "application/json")
	request.Header.Set("X-Auth-Token", token)
	if err != nil {
		return fmt.Errorf("%s", err)
	}
	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("%s", err)
	}
	defer resp.Body.Close()
	log.Info().Msgf("Add user to project: %d", resp.StatusCode)
	if resp.StatusCode != 204 {
		return fmt.Errorf("Error: %d", resp.StatusCode)
	}
	return nil
}

func createProjectOnEndpoints(token string, ns string, uid string, endpoints []Endpoint) {
	for _, endpoint := range endpoints {
		_, _, err := createProject(token, endpoint, uid, ns)
		if err != nil {
			log.Error().Str("endpoint", endpoint.ID).Str("ns", ns).Msg("Failed to create project on endpoint")
		}
	}
}

func createProject(token string, endpoint Endpoint, uid string, ns string) (string, string, error) {
	// config := terraConfig.LoadConfig()
	if !endpoint.PerNSProject {
		return endpoint.DefaultProjectID, endpoint.DefaultProjectName, nil
	}
	projectExist, projectErr := projectExists(token, ns, endpoint)
	if projectErr == nil {
		return projectExist.OID, ns, nil
	}

	openstackProjectInfo := openstackProjectInfoDef{
		Name:        ns,
		Description: fmt.Sprintf("goterra project for user %s", uid),
		IsDomain:    false,
		Enabled:     true,
		Domain:      endpoint.DomainID,
	}

	openstackProject := openstackProjectDef{
		Project: openstackProjectInfo,
	}

	jsonData, _ := json.Marshal(openstackProject)
	request, err := http.NewRequest("POST", fmt.Sprintf("%s/v3/projects", endpoint.KeystoneURL), bytes.NewBuffer(jsonData))
	request.Header.Set("Content-type", "application/json")
	request.Header.Set("X-Auth-Token", token)
	if err != nil {
		return "", "", fmt.Errorf("%s", err)
	}
	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return "", "", fmt.Errorf("%s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		return "", "", fmt.Errorf("Error: %d", resp.StatusCode)
	}
	var newProject map[string]interface{}
	body, err := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, &newProject)
	log.Error().Msgf("project %s", body)

	projectDetails := newProject["project"].(map[string]interface{})

	biosphereNS := &BiosphereNS{
		ID:       ns,
		OID:      projectDetails["id"].(string),
		Endpoint: endpoint.ID,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// biosphereNSCollection := mongoClient.Database(config.Mongo.DB).Collection("biosphere_ns")
	biosphereNSCollection.InsertOne(ctx, biosphereNS)
	// Update in-memory list too
	if _, ok := Namespaces[ns]; !ok {
		Namespaces[ns] = make(map[string]string)
	}
	Namespaces[ns][endpoint.ID] = biosphereNS.OID

	if endpoint.PerNSProject {
		err := createKeyPair(token, endpoint, biosphereNS.OID)
		if err != nil {
			log.Error().Str("uid", uid).Str("ns", ns).Str("endpoint", endpoint.ID).Msgf("%s", err)
		}
	}

	return biosphereNS.OID, ns, nil
}

func createKeyPair(token string, endpoint Endpoint, projectID string) error {
	client := http.Client{}
	keypairData := make(map[string]interface{})
	keypairData["name"] = endpoint.KeypairDefault
	keypairData["type"] = "ssh"
	keypair := make(map[string]interface{})
	keypair["keypair"] = keypairData
	jsonData, _ := json.Marshal(keypair)
	//log.Error().Msgf("Send %s", string(jsonData))
	request, err := http.NewRequest("POST", fmt.Sprintf("%s/v2.1/%s/os-keypairs", endpoint.NovaURL, projectID), bytes.NewBuffer(jsonData))
	request.Header.Set("Content-type", "application/json")
	request.Header.Set("X-Auth-Token", token)
	if err != nil {
		return fmt.Errorf("keypair creation error: %s", err)
	}
	resp, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("keypair creation error: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		return fmt.Errorf("User creation error %d", resp.StatusCode)
	}
	return nil
}

func createUserOnEndpoints(token string, uid string, endpoints []Endpoint) {
	for _, endpoint := range endpoints {
		_, err := createUser(token, endpoint, uid)
		if err != nil {
			log.Error().Str("endpoint", endpoint.ID).Str("user", uid).Msg("Failed to create user on endpoint")
		}
	}
}

func createUser(token string, endpoint Endpoint, uid string) (string, error) {
	client := http.Client{}

	buser, buserErr := userExists(token, uid, endpoint)
	if buserErr == nil {
		// Exists
		log.Info().Str("endpoint", endpoint.ID).Msg("already exists")
		return buser.OID, nil
	}

	// Create user and add to endpoint
	userData := make(map[string]interface{})
	userData["default_project_id"] = endpoint.DefaultProjectID
	userData["domain_id"] = endpoint.DomainID
	userData["enabled"] = true
	userData["name"] = uid
	userData["password"] = terraUtils.RandStringBytes(20)
	user := openstackUserDef{
		User: userData,
	}
	jsonData, _ := json.Marshal(user)
	//log.Error().Msgf("Send %s", string(jsonData))
	request, err := http.NewRequest("POST", fmt.Sprintf("%s/v3/users", endpoint.KeystoneURL), bytes.NewBuffer(jsonData))
	request.Header.Set("Content-type", "application/json")
	request.Header.Set("X-Auth-Token", token)
	if err != nil {
		return "", fmt.Errorf("User creation error: %s", err)
	}
	resp, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("User creation error: %s", err)
	}
	defer resp.Body.Close()
	var newUser map[string]interface{}
	body, err := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, &newUser)
	log.Error().Msgf("user %s", body)

	if resp.StatusCode != 201 {
		return "", fmt.Errorf("User creation error %d: %s", resp.StatusCode, body)
	}

	userDetails := newUser["user"].(map[string]interface{})

	userID := userDetails["id"].(string)

	// Crypt password
	config := terraConfig.LoadConfig()

	hasher := md5.New()
	hasher.Write([]byte(config.Fernet[0]))
	secret := hex.EncodeToString(hasher.Sum(nil))

	block, cipherErr := aes.NewCipher([]byte(secret))
	if cipherErr != nil {
		log.Error().Msgf("Failed secret cypher: %s", cipherErr)
		return "", fmt.Errorf("%s", cipherErr)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("%s", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("%s", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(userData["password"].(string)), nil)
	cryptedPwd := base64.StdEncoding.EncodeToString(ciphertext)

	// Add credentials to endpoint
	endpointSecret := &terraModel.EndPointSecret{
		UID:       uid,
		UserName:  uid,
		EndPoint:  endpoint.ID,
		Password:  cryptedPwd,
		Namespace: "biosphere",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpointSecretCollection := mongoClient.Database(config.Mongo.DB).Collection("endpointsecrets")
	endpointSecretCollection.InsertOne(ctx, endpointSecret)

	biosphereUser := BiosphereUser{
		UID:      uid,
		Endpoint: endpoint.ID,
		OID:      userID,
	}

	// biosphereUserCollection := mongoClient.Database(config.Mongo.DB).Collection("biosphere_users")
	biosphereUserCollection.InsertOne(ctx, biosphereUser)
	// Update in-memory list too
	if _, ok := Users[uid]; !ok {
		Users[uid] = make(map[string]string)
	}
	Users[uid][endpoint.ID] = userID

	return userID, nil
}

// GetToken ask keystone a token for endpoint
func GetToken(endpoint Endpoint, projectID string) (string, error) {
	client := http.Client{}
	methods := []string{"password"}
	password := make(map[string]map[string]string)
	password["user"] = make(map[string]string)
	password["user"]["id"] = endpoint.User
	password["user"]["password"] = endpoint.Password
	ident := openstackIdentityDef{
		Methods:  methods,
		Password: password,
	}
	scope := make(map[string]map[string]interface{})
	// scope["domain"] = make(map[string]string)
	// scope["domain"]["id"] = endpoint.DomainID
	scope["project"] = make(map[string]interface{})
	scope["project"]["id"] = projectID
	scope["project"]["domain"] = make(map[string]string)
	scope["project"]["domain"].(map[string]string)["id"] = endpoint.DomainID
	auth := openstackAuthDef{
		Identity: ident,
		Scope:    scope,
	}
	data := openstackAuthReqDef{
		Auth: auth,
	}
	jsonData, _ := json.Marshal(data)
	log.Error().Msgf("Send %s", string(jsonData))
	request, err := http.NewRequest("POST", fmt.Sprintf("%s/v3/auth/tokens", endpoint.KeystoneURL), bytes.NewBuffer(jsonData))
	request.Header.Set("Content-type", "application/json")
	if err != nil {
		return "", fmt.Errorf("%s", err)
	}
	resp, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("%s", err)
	}
	defer resp.Body.Close()
	// body, err := ioutil.ReadAll(resp.Body)
	// log.Error().Msgf("Status: %d, Headers: %+v, Body %s", resp.StatusCode, resp.Header, body)
	token := resp.Header.Get("X-Subject-Token")
	if token == "" {
		return "", fmt.Errorf("Failed to get token")
	}
	return token, nil
}
