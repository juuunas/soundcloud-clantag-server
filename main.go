package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	memcache_store "github.com/eko/gocache/store/memcache/v4"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/monitor"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/storage/sqlite3/v2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type User struct {
	gorm.Model
	SoundCloudId string `gorm:"index;primaryKey"`
	ClanID       *uint
	Clan         *Clan
	OwnedClan    *Clan `gorm:"foreignKey:OwnerID"`
	ClanJoinDate time.Time
	SoundCloud   *SCUser `gorm:"-"`
}

type Clan struct {
	gorm.Model
	Name    string
	Tag     string
	Color   string
	OwnerID string
	Owner   User
	Members []User `gorm:"foreignKey:ClanID"`
}

type SCUser struct {
	ID        int    `json:"id"`
	AvatarURL string `json:"avatar_url"`
	Username  string `json:"username"`
}

type SCResponse struct {
	Collection []SCUser `json:"collection"`
}

type SCUnreadResponse struct {
	Collection []struct {
		LastMessage struct {
			Content string `json:"content"`
			Sender  SCUser `json:"sender"`
		} `json:"last_message"`
	} `json:"collection"`
}

type VerificationResponse struct {
	Status string `json:"status"`
}

type (
	ErrorResponse struct {
		Error       bool
		FailedField string
		Tag         string
		Value       interface{}
	}

	XValidator struct {
		validator *validator.Validate
	}
)

var validate = validator.New(validator.WithRequiredStructEnabled())

func (v XValidator) Validate(data interface{}) []ErrorResponse {
	validationErrors := []ErrorResponse{}

	errs := validate.Struct(data)
	if errs != nil {
		for _, err := range errs.(validator.ValidationErrors) {
			// In this case data object is actually holding the User struct
			var elem ErrorResponse

			elem.FailedField = err.Field() // Export struct field name
			elem.Tag = err.Tag()           // Export struct tag
			elem.Value = err.Value()       // Export field value
			elem.Error = true

			validationErrors = append(validationErrors, elem)
		}
	}

	return validationErrors
}

var verificationCodes = map[string]string{}

func GenerateOTP(maxDigits uint32) string {
	bi, err := rand.Int(
		rand.Reader,
		big.NewInt(int64(math.Pow(10, float64(maxDigits)))),
	)
	if err != nil {
		panic(err)
	}

	otp := fmt.Sprintf("%0*d", maxDigits, bi)
	_, exists := verificationCodes[otp]
	if exists {
		return GenerateOTP(6)
	}

	return otp
}

func getUserIDStrFromUser(user SCUser) string {
	return strconv.Itoa(int(user.ID))
}

func sendRequest(method, url string, headers map[string]string) ([]byte, error) {
	client := &http.Client{}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	return body, nil
}

func unmarshalResponse(body []byte, result interface{}) error {
	if err := json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("error unmarshalling response: %v", err)
	}
	return nil
}

func getUserByID(id string) SCUser {
	url := fmt.Sprintf("https://api-v2.soundcloud.com/users/%s?client_id=AADp6RRMinJzmrc26qh92jqzJOF69SwF", id)

	body, err := sendRequest("GET", url, nil)
	if err != nil {
		fmt.Println(err)
		return SCUser{}
	}

	var user SCUser
	if err := unmarshalResponse(body, &user); err != nil {
		fmt.Println(err)
		return SCUser{}
	}

	return user
}

func getUserBySearch(name string) SCUser {
	url := fmt.Sprintf("https://api-v2.soundcloud.com/search/users?q=%s&client_id=AADp6RRMinJzmrc26qh92jqzJOF69SwF&limit=1", name)

	body, err := sendRequest("GET", url, nil)
	if err != nil {
		fmt.Println(err)
		return SCUser{}
	}

	var result SCResponse
	if err := unmarshalResponse(body, &result); err != nil {
		fmt.Println(err)
		return SCUser{}
	}

	if len(result.Collection) > 0 {
		return result.Collection[0]
	}
	return SCUser{}
}

func getSCUserByID(id string) SCUser {
	url := fmt.Sprintf("https://api-v2.soundcloud.com/users/%s?client_id=AADp6RRMinJzmrc26qh92jqzJOF69SwF", id)

	body, err := sendRequest("GET", url, nil)
	if err != nil {
		fmt.Println(err)
		return SCUser{}
	}

	var result SCUser
	if err := unmarshalResponse(body, &result); err != nil {
		fmt.Println(err)
		return SCUser{}
	}

	return result
}

func hasMessageWithIDAndOTP(id, otp string) bool {
	url := "https://api-v2.soundcloud.com/users/1257683746/conversations/unread?limit=100&client_id=AADp6RRMinJzmrc26qh92jqzJOF69SwF"
	headers := map[string]string{"Authorization": "OAuth "}

	body, err := sendRequest("GET", url, headers)
	if err != nil {
		fmt.Println(err)
		return false
	}

	var result SCUnreadResponse
	if err := unmarshalResponse(body, &result); err != nil {
		fmt.Println(err)
		return false
	}

	for _, element := range result.Collection {
		if strconv.Itoa(int(element.LastMessage.Sender.ID)) == id && element.LastMessage.Content == otp {
			return true
		}
	}

	return false
}

func getUserWithToken(token string) SCUser {
	url := "https://api-v2.soundcloud.com/me"
	headers := map[string]string{"Authorization": "OAuth " + token}

	body, err := sendRequest("GET", url, headers)
	if err != nil {
		fmt.Println(err)
		return SCUser{}
	}

	var user SCUser
	if err := unmarshalResponse(body, &user); err != nil {
		fmt.Println(err)
		return SCUser{}
	}

	return user
}

func userWithIDExists(db *gorm.DB, id string) bool {
	if err := db.Where(User{SoundCloudId: id}).First(&User{}).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		return false
	}
	return true
}

func attachSCUserToUser(user *User, ctx context.Context, cacheUtility *CacheUtility) {
	var scuser SCUser
	ownerID := user.SoundCloudId
	key := fmt.Sprintf("user:%s", ownerID)
	if err := cacheUtility.Get(ctx, key, &scuser); err != nil {
		scuser = getSCUserByID(ownerID)
		cacheUtility.Set(ctx, key, &scuser, 5*time.Hour)
	}
	user.SoundCloud = &scuser
}

const SessionKey string = "session"

func SessionExists(store *session.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to retrieve session",
			})
		}

		if sess.Get("id") == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Not logged in",
			})
		}

		c.Locals(SessionKey, sess)
		return c.Next()
	}
}

type CacheUtility struct {
	cacheManager *cache.Cache[[]byte]
}

func NewCacheUtility(addresses ...string) *CacheUtility {
	memcachedClient := memcache.New(addresses...)
	memcachedStore := memcache_store.NewMemcache(
		memcachedClient,
		store.WithExpiration(30*time.Minute),
	)
	cacheManager := cache.New[[]byte](memcachedStore)
	return &CacheUtility{cacheManager: cacheManager}
}

func (c *CacheUtility) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	jsonData, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return c.cacheManager.Set(ctx, key, jsonData, store.WithExpiration(expiration))
}

func (c *CacheUtility) Get(ctx context.Context, key string, dest interface{}) error {
	cachedData, err := c.cacheManager.Get(ctx, key)
	if err != nil {
		return err
	}

	return json.Unmarshal(cachedData, dest)
}

func seedDatabase(db *gorm.DB) {
	for i := 1; i < 51; i++ {
		user := User{
			SoundCloudId: strconv.Itoa(i),
			ClanJoinDate: time.Now(),
		}
		db.Create(&user)
	}

	clans := []Clan{
		{Name: "The First Clan", Tag: "TC1", Color: "#FF0000"},
		{Name: "The Second Clan", Tag: "TC2", Color: "#00FF00"},
		{Name: "The Third Clan", Tag: "TC3", Color: "#0000FF"},
		{Name: "The Fourth Clan", Tag: "TC4", Color: "#FFFF00"},
		{Name: "The Fifth Clan", Tag: "TC5", Color: "#FF00FF"},
	}
	for i, clan := range clans {
		db.Create(&clan)

		members := []User{
			{ClanID: &clan.ID, SoundCloudId: strconv.Itoa(i*5 + 0)},
			{ClanID: &clan.ID, SoundCloudId: strconv.Itoa(i*5 + 1)},
			{ClanID: &clan.ID, SoundCloudId: strconv.Itoa(i*5 + 2)},
			{ClanID: &clan.ID, SoundCloudId: strconv.Itoa(i*5 + 3)},
			{ClanID: &clan.ID, SoundCloudId: strconv.Itoa(i*5 + 4)},
		}
		for _, member := range members {
			db.Create(&member)
		}
	}
}

func main() {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Info),
	})
	if err != nil {
		panic("failed to connect database")
	}

	myValidator := &XValidator{
		validator: validate,
	}

	cacheUtility := NewCacheUtility("127.0.0.1:11211")

	db.AutoMigrate(&User{}, &Clan{})

	app := fiber.New()
	app.Use(recover.New())
	app.Use(logger.New())

	sessionStore := sqlite3.New(sqlite3.Config{
		Database: "test.db",
	})
	store := session.New(session.Config{
		KeyLookup: "header:authorization",
		Storage:   sessionStore,
	})

	app.Use(cors.New(cors.Config{
		AllowOrigins:  "http://localhost:5173",
		ExposeHeaders: "Authorization",
	}))

	app.Get("/stats", func(c *fiber.Ctx) error {
		var userCount int64
		var clanCount int64

		userResult := db.Model(&User{}).Count(&userCount)
		if userResult.Error != nil {
			fmt.Println("Error counting users:", userResult.Error)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Something went wrong",
			})
		}

		clanResult := db.Model(&Clan{}).Count(&clanCount)
		if clanResult.Error != nil {
			fmt.Println("Error counting orders:", clanResult.Error)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Something went wrong",
			})
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"user": userCount,
			"clan": clanCount,
		})
	})

	app.Get("/session", SessionExists(store), func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{})
	})

	app.Get("/clans/me", SessionExists(store), func(c *fiber.Ctx) error {
		sess := c.Locals(SessionKey).(*session.Session)

		id := sess.Get("id").(string)

		var user User
		if err := db.Where(&User{SoundCloudId: id}).Preload("Clan.Members").Preload("Clan.Owner").First(&user).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Something went wrong",
			})
		}

		if user.Clan == nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Clan not found",
				"clan":  user,
			})
		}

		var scuser SCUser
		ownerID := user.Clan.Owner.SoundCloudId
		key := fmt.Sprintf("user:%s", ownerID)
		if err := cacheUtility.Get(ctx, key, &scuser); err != nil {
			scuser = getSCUserByID(ownerID)
			cacheUtility.Set(ctx, key, &scuser, 5*time.Hour)
		}

		user.Clan.Owner.SoundCloud = &scuser

		return c.Status(fiber.StatusOK).JSON(user.Clan)
	})

	app.Get("/clans/:id", func(c *fiber.Ctx) error {
		id, err := c.ParamsInt("id")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid parameter",
			})
		}

		var clan Clan
		if err := db.Preload("Members").Preload("Owner").First(&clan, id).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Clan not found",
			})
		}

		var wg sync.WaitGroup
		for i := range clan.Members {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				attachSCUserToUser(&clan.Members[i], ctx, cacheUtility)
			}(i)
		}
		wg.Wait()

		return c.Status(fiber.StatusOK).JSON(clan)
	})

	app.Post("/clans/create", SessionExists(store), func(c *fiber.Ctx) error {
		sess := c.Locals(SessionKey).(*session.Session)

		type ClanCreate struct {
			Name  string `json:"name" validate:"required"`
			Tag   string `json:"tag" validate:"required,max=5"`
			Color string `json:"color" validate:"required,iscolor"`
		}

		clan := new(ClanCreate)
		if err := c.BodyParser(clan); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		if errs := myValidator.Validate(clan); len(errs) > 0 && errs[0].Error {
			errMsgs := make([]string, 0)

			for _, err := range errs {
				errMsgs = append(errMsgs, fmt.Sprintf(
					"[%s]: '%v' | Needs to implement '%s'",
					err.FailedField,
					err.Value,
					err.Tag,
				))
			}

			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": strings.Join(errMsgs, " and "),
			})
		}

		id := sess.Get("id").(string)

		cclan := Clan{
			Name:    clan.Name,
			Tag:     clan.Tag,
			Color:   clan.Color,
			OwnerID: id,
		}

		result := db.Create(&cclan)
		if result.Error != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Something went wrong",
			})
		}

		var user User
		if err := db.First(&user, "sound_cloud_id = ?", id).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Something went wrong",
			})
		}

		user.ClanID = &cclan.ID
		user.ClanJoinDate = time.Now()

		if err := db.Save(&user).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Something went wrong",
			})
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{})
	})

	app.Post("/logout", SessionExists(store), func(c *fiber.Ctx) error {
		sess := c.Locals(SessionKey).(*session.Session)

		if err := sess.Destroy(); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to logout",
			})
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{})
	})

	app.Post("/registerWithToken", func(c *fiber.Ctx) error {
		type LoginInfo struct {
			Token string `json:"token"`
		}

		info := new(LoginInfo)
		if err := c.BodyParser(info); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		user := getUserWithToken(info.Token)
		if user == (SCUser{}) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Token is invalid",
			})
		}

		id := getUserIDStrFromUser(user)
		if userWithIDExists(db, id) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "User with that id exists",
			})
		}

		result := db.Create(&User{SoundCloudId: id})
		if result.Error != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Something went wrong",
			})
		}

		sess, err := store.Get(c)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to retrieve session",
			})
		}

		if sess.Fresh() {
			sess.Set("id", id)

			if err := sess.Save(); err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to save session",
				})
			}

			return c.Status(fiber.StatusOK).JSON(fiber.Map{
				"id":       id,
				"username": user.Username,
			})
		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Already logged in",
		})
	})

	app.Post("/registerWithMessage", func(c *fiber.Ctx) error {
		type Request struct {
			ProfileURLName string `json:"profileurlname"`
		}

		req := new(Request)
		if err := c.BodyParser(req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request",
			})
		}

		user := getUserBySearch(req.ProfileURLName)
		if user == (SCUser{}) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "User not found",
			})
		}

		id := getUserIDStrFromUser(user)
		if userWithIDExists(db, id) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "User with that id exists",
			})
		}

		otp := GenerateOTP(6)
		verificationCodes[otp] = id

		return c.JSON(fiber.Map{
			"otp": otp,
		})
	})

	app.Post("/completeMessageRegistration", func(c *fiber.Ctx) error {
		type Request struct {
			Otp string `json:"otp"`
		}

		req := new(Request)
		if err := c.BodyParser(req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request",
			})
		}

		id, ok := verificationCodes[req.Otp]
		if !ok {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Something went wrong",
			})
		}

		delete(verificationCodes, req.Otp)

		user := getUserByID(id)
		if user == (SCUser{}) {
			delete(verificationCodes, id)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Something went wrong",
			})
		}

		result := db.Create(&User{SoundCloudId: id})
		if result.Error != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Something went wrong",
			})
		}

		sess, err := store.Get(c)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to retrieve session",
			})
		}

		if sess.Fresh() {
			sess.Set("id", id)

			if err := sess.Save(); err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to save session",
				})
			}

			return c.Status(fiber.StatusOK).JSON(fiber.Map{
				"id":       id,
				"username": user.Username,
			})

		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Something went wrong",
		})
	})

	app.Get("/events/:otp", func(c *fiber.Ctx) error {
		otp := c.Params("otp")
		c.Set("Content-Type", "text/event-stream")
		c.Set("Cache-Control", "no-cache")
		c.Set("Connection", "keep-alive")

		timer := time.NewTimer(1 * time.Minute)
		defer timer.Stop()

		for {
			select {
			case <-timer.C:
				response := VerificationResponse{
					Status: "expired",
				}
				delete(verificationCodes, otp)
				data, _ := json.Marshal(response)
				fmt.Fprintf(c, "data: %s\n\n", data)
				return nil

			case <-time.After(time.Second * 10):
				if hasMessageWithIDAndOTP(verificationCodes[otp], otp) {
					response := VerificationResponse{
						Status: "verified",
					}
					data, _ := json.Marshal(response)
					fmt.Fprintf(c, "data: %s\n\n", data)
					return nil
				}
			}
		}
	})

	app.Get("/clantag", func(c *fiber.Ctx) error {
		query := c.Queries()
		userId := query["id"]

		if userId == "" {
			return c.Status(fiber.StatusBadRequest).SendString("Missing required query parameter: id")
		}

		return c.JSON(fiber.Map{
			"name":  fmt.Sprintf("#%s", userId),
			"color": "#669b31",
		})
	})

	app.Get("/metrics", monitor.New())

	log.Fatal(app.Listen(":3000"))
}
