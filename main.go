package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/etag"
	"github.com/gofiber/fiber/v2/middleware/monitor"
	"log"
	"strconv"
	"strings"
	"time"
)

var (
	ipCheck1   []string
	ipCheck2   []string
	privateKey *rsa.PrivateKey
	publicKey  rsa.PublicKey
)

type (
	Key struct {
		ip          string
		time        string
		checkPoints struct {
			checkPoint1 string
			checkPoint2 string
		}
	}
	Visited struct {
		point string
		time  string
		ip    string
	}
	checkBody struct {
		Key string `json:"key"`
	}
)

//nolint:funlen
//nolint:gocognit
func main() {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalln(err)
	}
	privateKey = privKey
	publicKey = privateKey.PublicKey

	// <editor-fold desc="Fiber Part">
	app := fiber.New(fiber.Config{
		Prefork: true,
	})
	// <editor-fold desc="Middleware">
	app.Use(etag.New(etag.Config{
		Weak: false,
	}))
	app.Get("/eb2uktai0twzDoNwHU7ynFqQGLL9NabJMhGTb3HDVoK3Sih32Q", monitor.New(monitor.ConfigDefault))
	// </editor-fold>
	// <editor-fold desc="Simple redirection">
	app.Get("/", func(c *fiber.Ctx) error {
		// check if they've already done it
		hash := hashIP(c.IP())
		// check if key is vaild
		cookie, _ := checkKey(c.Cookies("FUNNYKEY"), hash)
		if !cookie {
			// clear old key
			c.ClearCookie("FUNNYKEY")
			// if not, generate a new key
			return c.Redirect("https://link-center.net/224166/darkhub-key")
		}
		return c.Redirect("/getKey")
	})
	// </editor-fold>

	// <editor-fold desc="checkpoints">
	app.Get("/checkpoint/1", func(ctx *fiber.Ctx) error {
		// hash for ip
		hash := hashIP(ctx.IP())
		// make visited cookie
		v := Visited{
			point: "1",
			time:  strconv.FormatInt(time.Now().Unix(), 10),
			ip:    hash,
		}
		// enc it
		enc, worked := RsaOaepEncrypt(fmt.Sprintf("%s:%s:%s", v.point, v.time, v.ip))
		if !worked {
			return ctx.Status(500).SendString("Internal Server Error")
		}
		// add ip to ipcheck1
		ipCheck1 = append(ipCheck1, hash)
		// set cookie for user
		ctx.Cookie(&fiber.Cookie{
			Name:     "CHECKPOINT1",
			Value:    enc,
			Path:     "/",
			Expires:  time.Now().Add(time.Minute * 5),
			Secure:   true,
			HTTPOnly: true,
			SameSite: "strict",
		})
		// then send to the linkvertise
		return ctx.Redirect("https://linkvertise.com/224166/darkhub-checkpoint")
	})

	app.Get("/checkpoint/2", func(ctx *fiber.Ctx) error {
		// hash for ip
		hash := hashIP(ctx.IP())
		// check if the user visited 1
		if contains(ipCheck1, hash) {
			// check cookie
			c1 := ctx.Cookies("CHECKPOINT1")
			// if cookie is empty
			if len(c1) == 0 {
				ctx.Set("refresh", "5; url=/1")
				return ctx.Status(400).SendString("Did you do checkpoint 1?")
			}
			// make cookie for checkpoint 2
			v := Visited{
				point: "2",
				time:  strconv.FormatInt(time.Now().Unix(), 10),
				ip:    hash,
			}
			// enc it
			enc, worked := RsaOaepEncrypt(fmt.Sprintf("%s:%s:%s", v.point, v.time, v.ip))
			if !worked {
				return ctx.Status(500).SendString("Internal Server Error")
			}
			// remove from 1
			ipCheck1 = remove(ipCheck1, hash)
			// add to 2
			ipCheck2 = append(ipCheck2, hash)
			// set cookie for checkpoint 2
			ctx.Cookie(&fiber.Cookie{
				Name:     "CHECKPOINT2",
				Value:    enc,
				Path:     "/",
				Expires:  time.Now().Add(time.Minute * 5),
				Secure:   true,
				HTTPOnly: true,
				SameSite: "strict",
			})
			// then send to the keyPage
			return ctx.Redirect("../getKey")
		}
		// if user didn't visit 1
		return ctx.Redirect("./1")
	})
	// </editor-fold>
	app.Get("/getKey", func(ctx *fiber.Ctx) error {
		// get ip hashed
		hash := hashIP(ctx.IP())
		// check if the user already has a vaild key
		key := ctx.Cookies("FUNNYKEY")
		if key != "" {
			// check the key
			v, _ := checkKey(key, hash)
			if v {
				// send key
				return ctx.SendString(key)
			}
			// if it isn't clear it
			ctx.ClearCookie("FUNNYKEY")
			ctx.ClearCookie("CHECKPOINT1")
			ctx.ClearCookie("CHECKPOINT2")
			ctx.Set("refresh", "2; url=/")
			return ctx.SendString("Saved key is invalid.")
		}
		// check the user has been to both checkpoints
		c1 := ctx.Cookies("CHECKPOINT1")
		c2 := ctx.Cookies("CHECKPOINT2")
		// check if ipcheck2 has ip
		if contains(ipCheck2, hash) {
			if len(c1) == 0 || len(c2) == 0 {
				ctx.Set("refresh", "5; url=../")
				return ctx.Status(400).SendString("Failed to get key")
			}
			cp1, worked := RsaOaepDecrypt(c1)
			if !worked {
				ctx.Set("refresh", "5;")
				return ctx.Status(400).SendString("Failed to get key")
			}
			cp2, worked := RsaOaepDecrypt(c2)
			if !worked {
				ctx.Set("refresh", "5;")
				return ctx.Status(400).SendString("Failed to get key")
			}
			// parse cookies
			cp1Parsed := strings.Split(cp1, ":")
			cp2Parsed := strings.Split(cp2, ":")
			if len(cp1Parsed) < 3 || len(cp2Parsed) < 3 {
				ctx.ClearCookie("CHECKPOINT1")
				ctx.ClearCookie("CHECKPOINT2")
				ctx.Set("refresh", "5; url=/")
				return ctx.SendString("Previous key invalid")
			}
			// define checkpoints for cookie

			cps := struct {
				checkPoint1 string
				checkPoint2 string
			}{checkPoint1: cp1, checkPoint2: cp2}
			k := getKey(Key{ip: hash, time: strconv.Itoa(int(time.Unix(time.Now().Unix(), 0).Unix())), checkPoints: cps})
			ctx.Cookie(&fiber.Cookie{
				Name:     "FUNNYKEY",
				Value:    k,
				Path:     "/",
				Expires:  time.Now().Add(time.Hour * 24),
				Secure:   true,
				HTTPOnly: true,
				SameSite: "strict",
			})
			// remove ip
			ipCheck2 = remove(ipCheck2, hash)
			return ctx.SendString(k)
		}
		ctx.ClearCookie("CHECKPOINT1")
		ctx.ClearCookie("CHECKPOINT2")
		ctx.Set("refresh", "5; url=/")
		return ctx.SendString("Failed to get key")
	})
	app.Post("/checkKey", func(ctx *fiber.Ctx) error {
		if len(ctx.Body()) == 0 {
			return ctx.Send([]byte("no key"))
		}
		var e checkBody
		err := ctx.BodyParser(&e)
		if err != nil {
			return err
		}
		worked, text := checkKey(e.Key, hashIP(ctx.IP()))
		if !worked {
			return ctx.Status(403).Send([]byte(text))
		}
		ctx.Set("x-Worked-and-saved", "true")
		return ctx.Status(202).SendString(e.Key)
	})
	err = app.Listen(":5000")
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
	str := fmt.Sprintf("%s %s %s %s", k.ip, k.time, k.checkPoints.checkPoint1, k.checkPoints.checkPoint2)
	enc, worked := RsaOaepEncrypt(str)
	if !worked {
		return "Failed to make key"
	}
	return enc
}

func checkKey(key string, iphash string) (bool, string) {
	k, worked := RsaOaepDecrypt(key)
	if !worked {
		return false, "Failed to decrypt key"
	}
	kd := strings.Split(k, " ")
	// 0 is ip
	// 1 is time
	// 2 and 3 are checkpoints
	if len(kd) != 4 {
		return false, "bad key"
	}
	// checkpoint parsing
	cp1 := parseCheckpoint(kd[2])
	cp2 := parseCheckpoint(kd[3])
	// check if iphash doesn't match
	if kd[0] != iphash || cp1.ip != iphash || cp2.ip != iphash {
		return false, "ip not right"
	}
	// parse time
	cp1Time, err := strconv.Atoi(cp1.time)
	if err != nil {
		return false, "Failed to parse time"
	}
	cp2Time, err := strconv.Atoi(cp2.time)
	if err != nil {
		return false, "Failed to parse time"
	}
	// if greater than 30 seconds
	if (cp1Time - cp2Time) > 10000*3 {
		return false, "Took to long to do checkpoints"
	}
	// time parsing
	t, err := strconv.Atoi(kd[1])
	if err != nil {
		return false, "Failed to parse time"
	}
	// less than 24 hrs old
	if time.Unix(int64(t), 0).Add(time.Duration(86400)).Unix() <= time.Unix(time.Now().Unix(), 0).Unix() {
		return true, ""
	}
	// default
	return false, "Key Expired"
}

func parseCheckpoint(chp string) Visited {
	s := strings.Split(chp, ":")
	return Visited{
		point: s[0],
		time:  s[1],
		ip:    s[2],
	}
}

func hashIP(ip string) string {
	h := sha256.New()
	h.Write([]byte(ip))
	hash := hex.EncodeToString(h.Sum(nil))
	return hash
}

func RsaOaepEncrypt(secret string) (string, bool) {
	label := []byte("OAEP Encryption")
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &publicKey, []byte(secret), label)
	if err != nil {
		return "", false
	}
	return base64.StdEncoding.EncodeToString(ciphertext), true
}

func RsaOaepDecrypt(secret string) (string, bool) {
	label := []byte("OAEP Encryption")
	ciphertext, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", false
	}
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, label)
	if err != nil {
		return "", false
	}
	return string(plaintext), true
}

func remove(s []string, hash string) []string {
	for i, v := range s {
		if v == hash {
			s = append(s[:i], s[i+1:]...)
			break
		}
	}
	return s
}
