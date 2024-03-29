package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
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
var endpointCollection *mongo.Collection
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

func getEndpoint(id string) (*Endpoint, error) {
	if id == "" {
		return nil, fmt.Errorf("invalid id")
	}
	endpoint := Endpoint{}
	filter := bson.M{
		"id": id,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := endpointCollection.FindOne(ctx, filter).Decode(&endpoint)
	if err != nil {
		return nil, err
	}
	return &endpoint, nil
}

// UserCreateHandler triggers onUserCreate
var UserCreateHandler = func(w http.ResponseWriter, r *http.Request) {
	user, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid token"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	if !user.Admin {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "sorry, admin only...."}
		json.NewEncoder(w).Encode(respError)
		return
	}
	vars := mux.Vars(r)
	userID := vars["id"]
	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	action := terraModel.UserAction{
		Action: "user_create",
		UID:    userID,
		Data:   string(b),
	}

	keys, ok := r.URL.Query()["endpoint"]
	if ok || len(keys[0]) < 1 {
		endpointID := keys[0]
		endpoint, endpointErr := getEndpoint(endpointID)
		if endpointErr != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Header().Add("Content-Type", "application/json")
			respError := map[string]interface{}{"message": "invalid endpoint"}
			json.NewEncoder(w).Encode(respError)
			return
		}
		OnUserCreateEndpoint(action, *endpoint)
	} else {
		OnUserCreate(action)
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	resp := map[string]interface{}{"message": "done"}
	json.NewEncoder(w).Encode(resp)
}

// UserUpdateHandler triggers onUserUpdate
var UserUpdateHandler = func(w http.ResponseWriter, r *http.Request) {
	user, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid token"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	if !user.Admin {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "sorry, admin only...."}
		json.NewEncoder(w).Encode(respError)
		return
	}
	vars := mux.Vars(r)
	userID := vars["id"]
	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	action := terraModel.UserAction{
		Action: "user_update",
		UID:    userID,
		Data:   string(b),
	}

	keys, ok := r.URL.Query()["endpoint"]
	if ok || len(keys[0]) < 1 {
		endpointID := keys[0]
		endpoint, endpointErr := getEndpoint(endpointID)
		if endpointErr != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Header().Add("Content-Type", "application/json")
			respError := map[string]interface{}{"message": "invalid endpoint"}
			json.NewEncoder(w).Encode(respError)
			return
		}
		OnUserUpdateEndpoint(action, *endpoint)
	} else {
		OnUserUpdate(action)
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	resp := map[string]interface{}{"message": "done"}
	json.NewEncoder(w).Encode(resp)
}

// NSCreateHandler triggers onNSCreate
var NSCreateHandler = func(w http.ResponseWriter, r *http.Request) {
	user, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid token"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	if !user.Admin {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "sorry, admin only...."}
		json.NewEncoder(w).Encode(respError)
		return
	}
	vars := mux.Vars(r)
	userID := vars["id"]
	nsID := vars["nsid"]
	action := terraModel.UserAction{
		Action: "ns_update",
		UID:    userID,
		Data:   nsID,
	}

	keys, ok := r.URL.Query()["endpoint"]
	if ok || len(keys[0]) < 1 {
		endpointID := keys[0]
		endpoint, endpointErr := getEndpoint(endpointID)
		if endpointErr != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Header().Add("Content-Type", "application/json")
			respError := map[string]interface{}{"message": "invalid endpoint"}
			json.NewEncoder(w).Encode(respError)
			return
		}
		OnNSCreateEndpoint(action, *endpoint)
	} else {
		OnNSCreate(action)
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	resp := map[string]interface{}{"message": "done"}
	json.NewEncoder(w).Encode(resp)
}

// NSUpdateHandler triggers onNSUpdate
var NSUpdateHandler = func(w http.ResponseWriter, r *http.Request) {
	user, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid token"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	if !user.Admin {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "sorry, admin only...."}
		json.NewEncoder(w).Encode(respError)
		return
	}

	vars := mux.Vars(r)
	userID := vars["id"]
	nsID := vars["nsid"]
	action := terraModel.UserAction{
		Action: "ns_update",
		UID:    userID,
		Data:   nsID,
	}

	keys, ok := r.URL.Query()["endpoint"]
	if ok || len(keys[0]) < 1 {
		endpointID := keys[0]
		endpoint, endpointErr := getEndpoint(endpointID)
		if endpointErr != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Header().Add("Content-Type", "application/json")
			respError := map[string]interface{}{"message": "invalid endpoint"}
			json.NewEncoder(w).Encode(respError)
			return
		}
		OnNSUpdateEndpoint(action, *endpoint)
	} else {
		OnNSUpdate(action)
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	resp := map[string]interface{}{"message": "done"}
	json.NewEncoder(w).Encode(resp)
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

// OnUserUpdateEndpoint triggers endpoint hooks
func OnUserUpdateEndpoint(action terraModel.UserAction, endpoint Endpoint) {
	uidIndex := countBiosphereUsers(action.UID)
	log.Info().Msgf("should trigger hook on endpoints for user %d", uidIndex)
	if endpoint.Hook != "" {
		log.Info().Msgf("should trigger hook %s", endpoint.Hook)
		client := http.Client{}
		nsReq, hookErr := http.NewRequest("POST", fmt.Sprintf("%s/biosphere-ldap/user/%s/%d", endpoint.Hook, action.UID, uidIndex), bytes.NewBuffer([]byte(action.Data)))
		nsReq.Header.Set("X-API-KEY", endpoint.APIKey)
		nsReq.Header.Add("Content-Type", "application/json")
		if hookErr != nil {
			log.Error().Msgf("Failed to request hook %s", endpoint.Hook)
		}
		hookResp, hookRespErr := client.Do(nsReq)
		if hookRespErr != nil {
			log.Error().Msgf("Failed to request hook %s: %s", endpoint.Hook, hookRespErr)
			return
		}
		defer hookResp.Body.Close()
		if hookResp.StatusCode != 200 {
			log.Error().Msgf("Hook %s error: %s", endpoint.Hook, hookResp.Body)
		}

	}
}

// OnUserUpdate triggers endpoints hooks
func OnUserUpdate(action terraModel.UserAction) {
	config := LoadConfig()

	for _, endpoint := range config.Endpoints {
		OnUserUpdateEndpoint(action, endpoint)
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

	endpointCollection = mongoClient.Database(config.Mongo.DB).Collection("endpoint")

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

	r.HandleFunc("/biosphere/user", UserCreateHandler).Methods("POST")
	r.HandleFunc("/biosphere/user/{id}", UserUpdateHandler).Methods("PUT")
	r.HandleFunc("/biosphere/user/{id}/ns/{nsid}", NSCreateHandler).Methods("POST")
	r.HandleFunc("/biosphere/user/{id}/ns/{nsid}", NSUpdateHandler).Methods("PUT")

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
