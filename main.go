package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"log"
	"strconv"
	"strings"
	"time"
)

var (
	ipCheck1 []string
	ipCheck2 []string
	encKey   = "s=wpCZq1Ar9|e7K(r.\\:rLjt(>n(&1D5"
)

type (
	Key struct {
		ip   string
		time string
	}
	checkBody struct {
		Key string `json:"key"`
	}
)

func main() {
	// <editor-fold desc="Fiber Part">
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Redirect("https://link-center.net/224166/darkhub-checkpoint/1")
	})

	app.Get("/checkpoint/1", func(ctx *fiber.Ctx) error {
		hash := hashIP(ctx.IP())
		ipCheck1 = append(ipCheck1, hash)

		return ctx.Redirect("https://linkvertise.com/224166/darkhub-checkpoint/2")
	})

	app.Get("/checkpoint/2", func(ctx *fiber.Ctx) error {
		hash := hashIP(ctx.IP())
		if contains(ipCheck1, hash) {
			ipCheck2 = append(ipCheck2, hash)
			return ctx.Redirect("../getKey")
		}
		return ctx.Redirect("https://linkvertise.com/224166/darkhub-checkpoint/1")
	})
	app.Get("/getKey", func(ctx *fiber.Ctx) error {
		hash := hashIP(ctx.IP())
		if contains(ipCheck2, hash) {
			k := getKey(Key{ip: hash, time: time.Unix(time.Now().Unix(), 0).String()})
			return ctx.SendString("Key: " + k)
		}
		return ctx.SendString("BAD BOY")
	})
	app.Post("/checkKey", func(ctx *fiber.Ctx) error {
		if len(ctx.Body()) == 0 {
			return ctx.Send([]byte("WTF WHY NO KEY"))
		}
		var eeeeeee checkBody
		err := ctx.BodyParser(eeeeeee)
		if err != nil {
			return err
		}
		fmt.Println(eeeeeee)
		return ctx.Send([]byte("OK"))
	})
	err := app.Listen(":3000")
	if err != nil {
		return
	}
	// </editor-fold>
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func getKey(k Key) string {
	str := fmt.Sprintf("%s %s", k.ip, k.time)
	return AesEncrypt(str, encKey)
}

func checkKey(key string) (bool, string) {
	k := AesDecrypt(key, encKey)
	kd := strings.Split(k, " ")
	if len(kd) != 2 {
		return false, "WTF MAN BAD KEY"
	}
	t, err := strconv.Atoi(kd[1])
	if err != nil {
		log.Fatalln(err)
	}
	if time.Unix(int64(t), 0).Add(time.Duration(86400)).Unix() <= time.Unix(time.Now().Unix(), 0).Unix() {
		return false, "MEN KEY EXPIRED"
	}
	return true, ""
}

func hashIP(ip string) string {
	h := sha256.New()
	h.Write([]byte(ip))
	hash := hex.EncodeToString(h.Sum(nil))
	return hash
}
