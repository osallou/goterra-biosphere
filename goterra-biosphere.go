package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	terraConfig "github.com/osallou/goterra-lib/lib/config"
	terraModel "github.com/osallou/goterra-lib/lib/model"
	terraUser "github.com/osallou/goterra-lib/lib/user"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	mongo "go.mongodb.org/mongo-driver/mongo"
	mongoOptions "go.mongodb.org/mongo-driver/mongo/options"

	terraToken "github.com/osallou/goterra-lib/lib/token"
	"github.com/streadway/amqp"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	ldap "gopkg.in/ldap.v3"
)

// Version of server
var Version string

// DEPLOY is to start a new deployment
const DEPLOY string = "deploy"

// DESTROY is to destroy/delete a deployment
const DESTROY string = "destroy"

var mongoClient *mongo.Client
var nsCollection *mongo.Collection
var endpointDefaultsCollection *mongo.Collection
var biosphereUserCollection *mongo.Collection
var biosphereNSCollection *mongo.Collection

// Users is an in-memory representation of biosphereUserCollection
var Users map[string]map[string]string // User -> Endpoint -> openstack user id
// Namespaces is an in-memory representation of biosphereNSCollection
var Namespaces map[string]map[string]string // NS -> Endpoint -> openstack project id

// BiosphereUser defines user in biosphere
type BiosphereUser struct {
	UID      string `json:"uid"`
	OID      string `json:"oid"` // openstack user id
	Endpoint string `json:"endpoint"`
}

// BiosphereNS defines project in biosphere
type BiosphereNS struct {
	ID       string `json:"id"`
	OID      string `json:"oid"` // openstack project id
	Endpoint string `json:"endpoint"`
}

// UserDefaultsHandler returns user defaults for an endpoint/namespace
var UserDefaultsHandler = func(w http.ResponseWriter, r *http.Request) {
	user, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid token"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	vars := mux.Vars(r)
	userID := vars["id"]
	endpointID := vars["endpoint"]
	nsID := vars["ns"]

	if !user.Admin && user.UID != userID {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "not authorized"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	defaultsdb := BiosphereUser{}
	filter := bson.M{
		"uid":       userID,
		"endpoint":  endpointID,
		"namespace": nsID,
	}
	err = endpointDefaultsCollection.FindOne(ctx, filter).Decode(&defaultsdb)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "no defaults found"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	log.Debug().Str("user", userID).Str("endpoint", endpointID).Msgf("get defaults %+v", defaultsdb)
	w.Header().Add("Content-Type", "application/json")
	resp := map[string]interface{}{"defaults": defaultsdb}
	json.NewEncoder(w).Encode(resp)

}

// HomeHandler manages base entrypoint
var HomeHandler = func(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{"version": Version, "message": "ok"}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func countBiosphereUsers(uid string) int64 {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{}
	cursor, nbErr := biosphereUserCollection.Find(ctx, filter)
	if nbErr != nil {
		log.Error().Msgf("Failed to count number of users")
		return 0
	}
	var counter int64
	for cursor.Next(ctx) {
		var bUser BiosphereUser
		cursor.Decode(&bUser)
		if bUser.UID == uid {
			break
		} else {
			counter++
		}
	}
	return counter
}

// OnUserUpdate creates user in ldap if necessary and adds ssh key
func OnUserUpdate(action terraModel.UserAction) {
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

	var UID int64
	sr, err := l.Search(searchRequest)
	if err != nil || len(sr.Entries) == 0 {
		log.Info().Msgf("ldap user not found, creating it: %s", err)
		req := ldap.NewAddRequest(fmt.Sprintf("uid=%s,ou=%s,%s", user.UID, config.Users.Ldap.OU, config.Users.Ldap.DN), nil)
		req.Attribute("homeDirectory", []string{userHome})
		req.Attribute("cn", []string{user.Email})
		req.Attribute("sn", []string{user.UID})
		req.Attribute("gidNumber", []string{fmt.Sprintf("%d", config.Users.Ldap.GID)})
		UID = config.Users.Ldap.MinUID + countBiosphereUsers(user.UID)
		req.Attribute("uidNumber", []string{fmt.Sprintf("%d", UID)})
		req.Attribute("loginShell", []string{"/bin/bash"})
		req.Attribute("objectClass", []string{"PosixAccount", "inetOrgPerson"})
		err = l.Add(req)
		if err != nil {
			log.Error().Msgf("Failed to add user in ldap: %s", err)
			return
		}
	} else {
		log.Debug().Msgf("Got user in ldap: %+v", sr.Entries[0].Attributes)
		for _, attr := range sr.Entries[0].Attributes {
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

// GetGotEventAction gets a message from rabbitmq exchange
func GetGotEventAction() error {
	config := terraConfig.LoadConfig()
	if config.Amqp == "" {
		log.Error().Msg("no amqp defined")
		return fmt.Errorf("No AMQP config found")
	}
	conn, err := amqp.Dial(config.Amqp)
	if err != nil {
		log.Error().Msgf("failed to connect to %s", config.Amqp)
		return err
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		log.Error().Msg("failed to connect to amqp")
		return err
	}

	err = ch.ExchangeDeclare(
		"gotevent", // name
		"fanout",   // type
		true,       // durable
		false,      // auto-deleted
		false,      // internal
		false,      // no-wait
		nil,        // arguments
	)
	if err != nil {
		log.Error().Msg("failed to connect to open exchange")
		return err
	}

	queue, queueErr := ch.QueueDeclare(
		"gotevents",
		true,  // durable
		false, // auto-deleted
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	if queueErr != nil {
		log.Error().Msg("failed to create queue")
		return queueErr
	}

	bindErr := ch.QueueBind(queue.Name, "", "gotevent", false, nil)
	if bindErr != nil {
		log.Error().Msg("failed to bind queue to exchange")
		return bindErr
	}

	msgs, consumeErr := ch.Consume(
		queue.Name, // queue
		"",         // consumer
		false,      // auto-ack
		false,      // exclusive
		false,      // no-local
		false,      // no-wait
		nil,        // args
	)
	if consumeErr != nil {
		log.Error().Msg("failed to get messages")
		return consumeErr
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	go func(connection *amqp.Connection, channel *amqp.Channel) {
		sig := <-sigs
		channel.Close()
		connection.Close()
		log.Warn().Msgf("Closing AMQP channel and connection after signal %s", sig.String())
		log.Warn().Msg("Ready for shutdown")
	}(conn, ch)

	forever := make(chan bool)

	go func() {
		log.Debug().Msgf("listen for messages on %s", queue.Name)
		for d := range msgs {
			action := terraModel.UserAction{}
			err := json.Unmarshal(d.Body, &action)
			if err != nil {
				log.Error().Msgf("failed to decode message %s", d.Body)
				d.Ack(true)
				continue
			}
			// TODO test action create_user or pubkey
			log.Info().Msgf("got a message %+v", action)
			switch action.Action {
			case "user_create":
				OnUserCreate(action)
			case "user_update":
				OnUserUpdate(action)
			case "ns_create":
				OnNSCreate(action)
			case "ns_update":
				OnNSUpdate(action)
			default:
				log.Error().Msgf("invalid action %s", action.Action)
			}
			d.Ack(true)
		}
	}()

	<-forever

	return nil
}

// CheckToken checks Fernet token
func CheckToken(authToken string) (user terraUser.User, err error) {
	// config := terraConfig.LoadConfig()

	tokenStr := strings.Replace(authToken, "Bearer", "", -1)
	tokenStr = strings.TrimSpace(tokenStr)

	msg, errMsg := terraToken.FernetDecode([]byte(tokenStr))
	if errMsg != nil {
		return user, errMsg
	}
	json.Unmarshal(msg, &user)
	return user, nil
}

func main() {

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if os.Getenv("GOT_DEBUG") != "" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	config := terraConfig.LoadConfig()

	consulErr := terraConfig.ConsulDeclare("got-biosphere", "/biosphere")
	if consulErr != nil {
		log.Error().Msgf("Failed to register: %s", consulErr.Error())
		panic(consulErr)
	}

	var err error
	mongoClient, err = mongo.NewClient(mongoOptions.Client().ApplyURI(config.Mongo.URL))
	if err != nil {
		log.Error().Msgf("Failed to connect to mongo server %s", config.Mongo.URL)
		os.Exit(1)
	}

	ctx, cancelMongo := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelMongo()

	err = mongoClient.Connect(ctx)
	if err != nil {
		log.Error().Msgf("Failed to connect to mongo server %s", config.Mongo.URL)
		os.Exit(1)
	}
	endpointDefaultsCollection = mongoClient.Database(config.Mongo.DB).Collection("user_ep_defaults")

	Users = make(map[string]map[string]string)
	Namespaces = make(map[string]map[string]string)
	filter := bson.M{}

	biosphereUserCollection = mongoClient.Database(config.Mongo.DB).Collection("biosphere_users")
	cursor, listErr := biosphereUserCollection.Find(ctx, filter)
	if listErr == nil {
		for cursor.Next(ctx) {
			var bUser BiosphereUser
			cursor.Decode(&bUser)
			if _, ok := Users[bUser.UID]; !ok {
				Users[bUser.UID] = make(map[string]string)
			}
			Users[bUser.UID][bUser.Endpoint] = bUser.OID
		}
	}
	biosphereNSCollection = mongoClient.Database(config.Mongo.DB).Collection("biosphere_ns")
	cursor, listErr = biosphereNSCollection.Find(ctx, filter)
	if listErr == nil {
		for cursor.Next(ctx) {
			var bNS BiosphereNS
			cursor.Decode(&bNS)
			if _, ok := Namespaces[bNS.ID]; !ok {
				Namespaces[bNS.ID] = make(map[string]string)
			}
			Namespaces[bNS.ID][bNS.Endpoint] = bNS.OID
		}
	}

	go GetGotEventAction()

	r := mux.NewRouter()
	r.HandleFunc("/biosphere", HomeHandler).Methods("GET")
	r.HandleFunc("/biosphere/user/{id}/endpoint/{endpoint}/ns/{ns}", UserDefaultsHandler).Methods("GET")

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
