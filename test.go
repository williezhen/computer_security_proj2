package main

import (
	"fmt"
	"github.com/google/uuid"
)

func main() {
	u := uuid.New()
	fmt.Println(u)
	fmt.Println(u.String()[:len(u.String())-2] + "qq")
	//res := u.String()[:len(u.String())-2] + "qq"
	fmt.Println(u.String()) //+ u.String()[len(u.String())-2:]))
	fmt.Println(uuid.ParseBytes([]byte(u.String())))
}
