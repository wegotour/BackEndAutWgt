package PasetoBackend

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	Email        string `bson:"email,omitempty" json:"email,omitempty"`
	Username     string `json:"username" bson:"username"`
	Password     string `json:"password" bson:"password"`
	PasswordHash string `json:"passwordhash" bson:"passwordhash"`
	Role         string `json:"role,omitempty" bson:"role,omitempty"`
	Token        string `json:"token,omitempty" bson:"token,omitempty"`
	Private      string `json:"private,omitempty" bson:"private,omitempty"`
	Public       string `json:"public,omitempty" bson:"public,omitempty"`
}

type RegisterStruct struct {
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
}

type Credential struct {
	Status  bool   `json:"status" bson:"status"`
	Token   string `json:"token,omitempty" bson:"token,omitempty"`
	Message string `json:"message,omitempty" bson:"message,omitempty"`
}

type Response struct {
	Status  bool        `json:"status" bson:"status"`
	Message string      `json:"message" bson:"message"`
	Data    interface{} `json:"data" bson:"data"`
}

type Ticket struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Title       string             `bson:"title,omitempty" json:"title,omitempty"`
	Description string             `bson:"description,omitempty" json:"description,omitempty"`
	Deadline    string             `bson:"deadline,omitempty" json:"deadline,omitempty"`
	TimeStamp   TimeStamp          `bson:"timestamp,omitempty" json:"timestamp,omitempty"`
	IsDone      bool               `bson:"isdone,omitempty" json:"isdone,omitempty"`
}

type TimeStamp struct {
	CreatedAt time.Time `bson:"createdat,omitempty" json:"createdat,omitempty"`
	UpdatedAt time.Time `bson:"updatedat,omitempty" json:"updatedat,omitempty"`
}

type TicketList struct {
	Users      []User   `bson:"users,omitempty" json:"users,omitempty"`
	DataTicket []Ticket `bson:"ticketlist,omitempty" json:"ticketlist,omitempty"`
}

type TicketResponse struct {
	Status  bool   `bson:"status" json:"status"`
	Message string `bson:"message,omitempty" json:"message,omitempty"`
	Data    Ticket `bson:"data,omitempty" json:"data,omitempty"`
}
