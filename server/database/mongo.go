package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type DB struct {
	db         *mongo.Database
	ctx        context.Context
	cancleFunc context.CancelFunc
}

func (d *DB) ConnectToDB(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Second*10))
	defer cancel()
	uri := "mongodb://localhost:27017"
	option := options.Client().ApplyURI(uri)
	option.SetMaxPoolSize(10)
	client, err := mongo.Connect(ctx, option)
	if err != nil {
		cancel()
		return err
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		cancel()
		return err
	}

	d.db = client.Database(name)
	return nil
}

func (d *DB) updateCtx() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Second*10))
	d.ctx = ctx
	d.cancleFunc = cancel
}

func (d *DB) GetCollection(client *mongo.Database, name string) *mongo.Collection {
	return client.Collection(name)
}

const recordACollection string = "recordA"

func (d *DB) AddRecordA(r *DbRecordA) error {
	d.updateCtx()
	filter := bson.M{
		"Name":  r.Name,
		"Class": r.Class,
		"TTL":   r.TimeToLive,
		"IP":    r.IP,
	}
	r.ExpiredTime = time.Now().Add(time.Second * time.Duration(r.TimeToLive)).Unix()
	update := bson.M{
		"$set": r,
	}
	boolTrue := true
	option := options.UpdateOptions{
		Upsert: &boolTrue,
	}
	updateResult, err := d.GetCollection(d.db, recordACollection).
		UpdateOne(d.ctx, filter, update, &option)
	if err != nil {
		return err
	}
	if updateResult.UpsertedCount == 0 {
		return errors.New("No records were updated.")
	}
	return nil
}

func (d *DB) AddManyRecords(r *[]DbRecordA) error {
	for i := range *r {
		err := d.AddRecordA(&(*r)[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) CleanExpiredRecords() error {
	d.updateCtx()
	now := time.Now().Unix()
	filter := bson.M{
		"ExpiredTime": bson.M{
			"$lt": &now,
		},
	}
	deleteResult, err := d.GetCollection(d.db, recordACollection).
		DeleteMany(d.ctx, filter)
	if err != nil {
		return err
	}
	fmt.Printf("[MongoDB] Clean %d expired records.\n", deleteResult.DeletedCount)
	return nil
}

func (d *DB) QueryRecords(name string) ([]DbRecordA, error) {
	d.updateCtx()
	d.CleanExpiredRecords()
	option := options.FindOptions{}
	filter := bson.M{
		"Name": name,
	}
	var results []DbRecordA
	findResult, err := d.GetCollection(d.db, recordACollection).
		Find(d.ctx, filter, &option)
	if err != nil {
		return nil, err
	}
	for findResult.Next(d.ctx) {
		var r DbRecordA
		err = findResult.Decode(&r)
		if err != nil {
			fmt.Printf("[MongoDB] Decode found result failed. error info = %s", err.Error())
			continue
		}
		results = append(results, r)
	}
	if err = findResult.Err(); err != nil {
		return results, err
	}
	findResult.Close(d.ctx)
	if len(results) == 0 {
		return results, fmt.Errorf("MongoDB didn't find anything about %s", name)
	}
	return results, nil
}
