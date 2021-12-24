package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/etag"
	"github.com/gofiber/fiber/v2/middleware/monitor"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	"log"
	"strconv"
	"strings"
	"time"
)

const (
	checkpoint1CookieName = "COOKIE1"
	checkpoint2CookieName = "9GDPz917jNBZq00Dv9T5p8pcg"
	checkpoint1URL        = "https://linkvertise.com/224166/darkhub-key"
	checkpoint2URL        = "https://linkvertise.com/224166/darkhub-checkpoint"
	finishCookieName      = "usedfhytgrbuoeyrbftvuyoisrbnfovuysrbotguynsbrfuoivbhdfruyignbdouirthgbuifsdhngbkudryhngkbudfhgihujadamlogshwid"
	DONATORCOOKIENAME     = "Em3xfB5sURWGwayuN0CUtHYDNR8Lrh"
	version               = "2.0.1"
	staffCookieName       = "eXE6QrxMIrzT5ribgfvV1231qwesa"
)

type (
	checkpoint struct {
		Time       string `json:"time"`
		Checkpoint string `json:"checkpoint"`
		IP         string `json:"ip"`
	}
	checkKeyData struct {
		Key string `json:"key"`
	}
	KeyStub struct {
		IP string    `json:"ip"`
		T  time.Time `json:"t"`
	}
)

var (
	ks             *keyset.Handle
	ksPub          *keyset.Handle
	encLabel       = []byte("DARKHUBOPLOL")
	activeKeyStubs []string
)

//nolint:funlen
//nolint:gocognit
func main() {
	// <editor-fold desc="Initialization">
	k, err := keyset.NewHandle(hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate())
	if err != nil {
		panic(err)
	}
	ks = k
	ksPub, err = ks.Public()
	if err != nil {
		panic(err)
	}
	app := fiber.New(fiber.Config{
		AppName:     "Darkhub Key System V" + version,
		ProxyHeader: "CF-Connecting-IP",
	})
	// </editor-fold>

	// <editor-fold desc="Middleware">
	app.Static("/", "./assets")
	app.Get("/8mczIB7GXSs6ASWrAXoQfOMeg5OcEj", monitor.New(monitor.ConfigDefault))
	// etag
	app.Use(etag.New(etag.ConfigDefault))
	// </editor-fold>
	// <editor-fold desc="Routes">
	app.Get("/", func(c *fiber.Ctx) error {
		if cookie := c.Cookies(finishCookieName); len(cookie) > 0 {
			if checkKey(cookie, hashIP(c.IP())) {
				return c.Redirect("/getKey")
			}
			c.ClearCookie(finishCookieName)
		}
		if cookie := c.Cookies(DONATORCOOKIENAME); len(cookie) > 0 {
			if checkKey(cookie, hashIP(c.IP())) {
				return c.Redirect("/getKey")
			}
			c.ClearCookie(DONATORCOOKIENAME)
		}
		return c.Redirect(checkpoint1URL)
	})
	cps := app.Group("/checkpoint")
	// <editor-fold desc="Checkpoint 1">
	cps.Get("/1", func(c *fiber.Ctx) error {
		hash := hashIP(c.IP())
		str, err := generateCheckpoint(hash, "1")
		if err != nil {
			c.Set("refresh", "5; url=/")
			return c.Status(500).SendString("Failed to generate checkpoint data - Error Code: zhKIhTbv10GwTD91cAwM")
		}
		cookie := fiber.Cookie{
			Name:    checkpoint1CookieName,
			Value:   *str,
			Expires: time.Now().Add(time.Minute * 5),
		}
		c.Cookie(&cookie)
		return c.Redirect(checkpoint2URL)
	})
	// </editor-fold>
	// <editor-fold desc="Checkpoint 2">
	cps.Get("/2", func(c *fiber.Ctx) error {
		hash := hashIP(c.IP())
		checkpoint1 := c.Cookies(checkpoint1CookieName)
		cp1, err := decodeCheckpoint(checkpoint1)
		c.Set("refresh", "5; url=/checkpoint/1")
		if err != nil {
			return c.Status(500).SendString("Failed to decode checkpoint data - Error Code: DrNWaI38m2esAgRElGov")
		}
		if cp1.IP != hash {
			return c.Status(400).SendString("Bad request - Error Code: 9czyNcOmjLFAcZpy8N7T")
		}
		cp1t, err := strconv.Atoi(cp1.Time)
		if err != nil {
			return c.Status(400).SendString("Bad request - Error Code: MSNCOTUfPsBGmQzq1MA1")
		}
		if int64(cp1t)-time.Now().Unix() > int64(time.Minute*5) {
			return c.Status(400).SendString("Bad request - Error Code: BKno9mx7E0W7BlVvjDGg")
		}
		str, err := generateCheckpoint(hash, "2")
		if err != nil {
			return c.Status(500).SendString("Failed to generate checkpoint data - Error Code: Sn5sZyVtn8nTBIJYmGRy")
		}
		cookie := fiber.Cookie{
			Name:    checkpoint2CookieName,
			Value:   *str,
			Expires: time.Now().Add(time.Minute * 5),
		}
		c.Cookie(&cookie)
		c.Set("refresh", "")
		return c.Redirect("/getKey")
	})
	// </editor-fold>
	// </editor-fold>
	// <editor-fold desc="Get Key">
	app.Get("/getkey", func(c *fiber.Ctx) error {
		hash := hashIP(c.IP())
		if cook := c.Cookies(finishCookieName); len(cook) > 0 {
			if checkKey(cook, hash) {
				return c.SendString(cook)
			}
			c.ClearCookie(finishCookieName)
		}
		if cook := c.Cookies(DONATORCOOKIENAME); len(cook) > 0 {
			if checkKey(cook, hash) {
				return c.SendString(cook)
			}
			c.ClearCookie(DONATORCOOKIENAME)
		}
		checkpoint1 := c.Cookies(checkpoint1CookieName)
		checkpoint2 := c.Cookies(checkpoint1CookieName)
		cp1, err := decodeCheckpoint(checkpoint1)
		if err != nil {
			c.Set("refresh", "5; url=/checkpoint/1")
			return c.Status(400).SendString("Bad request - Error Code: W77ggxuPYvVejYKCsZrh")
		}
		cp2, err := decodeCheckpoint(checkpoint2)
		if err != nil {
			c.Set("refresh", "5; url=/checkpoint/2")
			return c.Status(400).SendString("Bad request - Error Code: voDCq8G4R51xM3eGWwpS")
		}
		if cp1.IP != hash || cp2.IP != hash {
			c.Set("refresh", "5; url=/checkpoint/1")
			return c.Status(400).SendString("Bad request - Error Code: QHyxIIrMXmwWAAJ2Ikyo")
		}
		key, err := genKey(*cp1, *cp2, hash, false, false)
		if err != nil {
			c.Set("refresh", "5;")
			return c.Status(500).SendString("Failed to generate key")
		}
		cookie := fiber.Cookie{
			Name:    finishCookieName,
			Value:   *key,
			Expires: time.Now().Add(time.Hour * 24),
		}
		c.Cookie(&cookie)
		c.ClearCookie(checkpoint1CookieName)
		c.ClearCookie(checkpoint2CookieName)
		return c.SendString(*key)
	})
	app.Get("/staff/O7KClOdBx0BeyM6E6TeD", func(c *fiber.Ctx) error {
		staffCookie := c.Cookies(staffCookieName)
		if staffCookie != "true" {
			return c.Status(404).SendString("Cannot GET /staff/O7KClOdBx0BeyM6E6TeD")
		}
		key, err := genKey(checkpoint{}, checkpoint{}, hashIP(c.IP()), true, false)
		if err != nil {
			c.Set("refresh", "5;")
			return c.Status(500).SendString("Failed to generate key")
		}
		return c.SendString(*key)
	})
	app.Get("/staff/3SGRFs9TEBIfShMcqQJ7", func(c *fiber.Ctx) error {
		// Generate donator key Stubs
		// get Ip hash
		hash := hashIP(c.IP())
		if cook := c.Cookies(staffCookieName); cook != "true" {
			return c.Status(404).SendString("Cannot GET /staff/3SGRFs9TEBIfShMcqQJ7")
		}
		stub, err := genKeyStub(hash)
		if err != nil {
			return err
		}
		activeKeyStubs = append(activeKeyStubs, stub)
		return c.SendString(stub)
	})
	app.Get("/donator/redeemKey", func(c *fiber.Ctx) error {
		ip := hashIP(c.IP())
		keyS := c.Query("key")
		if !contains(activeKeyStubs, keyS) {
			return c.Status(404).SendString("Invalid Key")
		}
		key, err := genKey(checkpoint{IP: ip, Checkpoint: "1", Time: "0"}, checkpoint{IP: ip, Checkpoint: "2", Time: "0"}, ip, false, true)
		if err != nil {
			return c.Status(500).SendString("Failed to generate key Key")
		}
		activeKeyStubs = remove(activeKeyStubs, keyS)
		cookie := fiber.Cookie{
			Name:    DONATORCOOKIENAME,
			Value:   *key,
			Expires: time.Now().Add(time.Hour * 10 * 200),
		}
		c.Cookie(&cookie)
		return c.SendString(*key)
	})
	// </editor-fold>
	// <editor-fold desc="check Key">
	app.Post("/checkkey", func(c *fiber.Ctx) error {
		k := new(checkKeyData)
		if err := c.BodyParser(k); err != nil {
			return c.Status(500).SendString("Internal Server Error - Error Code: QK0wMhbskyUJ0888labt")
		}
		if !checkKey(k.Key, hashIP(c.IP())) {
			return c.SendString("false")
		}
		return c.SendString("OK")
	})
	// </editor-fold>
	err = app.Listen(":5000")
	if err != nil {
		log.Panicln(err)
	}
}

// <editor-fold desc="hash">
func hashIP(ip string) string {
	h := sha256.New()
	h.Write([]byte(ip))
	hash := hex.EncodeToString(h.Sum(nil))
	return hash
}

// </editor-fold>
// <editor-fold desc="Encryption/Decrpytion">
func encrypt(data string) (*string, error) {
	enc, err := hybrid.NewHybridEncrypt(ksPub)
	if err != nil {
		return nil, err
	}
	ct, err := enc.Encrypt([]byte(data), encLabel)
	if err != nil {
		return nil, err
	}
	rt := base64.URLEncoding.EncodeToString(ct)
	return &rt, nil
}
func decrypt(data string) (*string, error) {
	dec, err := hybrid.NewHybridDecrypt(ks)
	if err != nil {
		return nil, err
	}
	ct, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	rt, err := dec.Decrypt(ct, encLabel)
	if err != nil {
		return nil, err
	}
	r := string(rt)
	return &r, nil
}

// </editor-fold>
// <editor-fold desc="Checkpoint Methods">
func generateCheckpoint(ip string, curCheckpoint string) (*string, error) {
	cp := checkpoint{
		Time:       fmt.Sprint(time.Now().Unix()),
		Checkpoint: curCheckpoint,
		IP:         ip,
	}
	j, err := json.Marshal(cp)
	if err != nil {
		return nil, err
	}
	rt, err := encrypt(string(j))
	if err != nil {
		return nil, err
	}
	return rt, nil
}
func decodeCheckpoint(data string) (*checkpoint, error) {
	cp := checkpoint{}
	dec, err := decrypt(data)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(*dec), &cp)
	if err != nil {
		return nil, err
	}
	return &cp, nil
}

// </editor-fold>
// <editor-fold desc="Key Methods">
func genKey(c1 checkpoint, c2 checkpoint, ip string, staff bool, donator bool) (*string, error) {
	cp1, err := json.Marshal(c1)
	if err != nil {
		return nil, err
	}
	cp2, err := json.Marshal(c2)
	if err != nil {
		return nil, err
	}
	encstring := fmt.Sprintf("%s %s %s %s %s %s", cp1, cp2, ip, fmt.Sprint(time.Now().Unix()), strconv.FormatBool(staff), strconv.FormatBool(donator))
	enc, err := encrypt(encstring)
	if err != nil {
		return nil, err
	}
	return enc, nil
}
func checkKey(key string, ip string) bool {
	dec, err := decrypt(key)
	if err != nil {
		return false
	}
	t := strings.Split(*dec, " ")
	if len(t) != 6 {
		return false
	}
	if t[4] == "true" {
		return true
	}
	var cp1, cp2 checkpoint
	err = json.Unmarshal([]byte(t[0]), &cp1)
	if err != nil {
		return false
	}
	err = json.Unmarshal([]byte(t[1]), &cp2)
	if err != nil {
		return false
	}
	hashed := t[2]
	ct, err := strconv.Atoi(t[3])
	if err != nil {
		return false
	}
	if cp1.IP != ip || cp2.IP != ip || hashed != ip {
		return false
	}
	if t[5] == "true" {
		return true
	}
	cookieTime := time.Unix(int64(ct), 0)
	return cookieTime.Unix() < time.Now().Add(time.Hour*24).Unix()
}

// <editor-fold desc="donator key">
func genKeyStub(ip string) (string, error) {
	keyS := KeyStub{
		IP: ip,
		T:  time.Now(),
	}
	d, err := json.Marshal(keyS)
	if err != nil {
		return "", err
	}
	enc, err := encrypt(string(d))
	if err != nil {
		return "", err
	}
	return *enc, nil
}

// </editor-fold>
// </editor-fold>
// <editor-fold desc="slice methods">
func remove(s []string, substring string) []string {
	for i, v := range s {
		if v == substring {
			s = append(s[:i], s[i+1:]...)
			break
		}
	}
	return s
}
func contains(s []string, substring string) bool {
	for _, v := range s {
		if v == substring {
			return true
		}
	}
	return false
}

// </editor-fold>
