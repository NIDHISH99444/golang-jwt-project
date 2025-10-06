package database

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

func DBInstance() *mongo.Client {

	_ = godotenv.Load(".env")

	uri := os.Getenv("MONGODB_URL")
	if uri == "" {
		log.Fatal("MONGODB_URL not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatal("mongo.Connect error: ", err)
	}

	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		log.Fatal("Mongo ping error: ", err)
	}

	log.Println("✅ Connected to MongoDB")
	return client
}

var Client *mongo.Client = DBInstance()

func OpenCollection(clint *mongo.Client, collectionName string) *mongo.Collection {
	var collection *mongo.Collection = clint.Database("cluster-0").Collection(collectionName)
	return collection
}
