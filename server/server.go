package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-zoox/logger"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/pkg/errors"
	echoSwagger "github.com/swaggo/echo-swagger"
	"go.uber.org/zap"

	"github.com/go-zoox/connect-middleware-for-echo"
	"github.com/go-zoox/random"
	"github.com/usememos/memos/api/auth"
	apiv1 "github.com/usememos/memos/api/v1"
	apiv2 "github.com/usememos/memos/api/v2"
	"github.com/usememos/memos/common/log"
	"github.com/usememos/memos/plugin/telegram"
	"github.com/usememos/memos/server/integration"
	"github.com/usememos/memos/server/profile"
	"github.com/usememos/memos/server/service"
	"github.com/usememos/memos/store"
	storeX "github.com/usememos/memos/store"
)

type Server struct {
	e *echo.Echo

	ID      string
	Secret  string
	Profile *profile.Profile
	Store   *store.Store

	// API services.
	apiV1Service *apiv1.APIV1Service
	apiV2Service *apiv2.APIV2Service

	// Asynchronous runners.
	backupRunner *service.BackupRunner
	telegramBot  *telegram.Bot
}

func NewServer(ctx context.Context, profile *profile.Profile, store *store.Store) (*Server, error) {
	e := echo.New()
	e.Debug = true
	e.HideBanner = true
	e.HidePort = true

	s := &Server{
		e:       e,
		Store:   store,
		Profile: profile,

		// Asynchronous runners.
		backupRunner: service.NewBackupRunner(store),
		telegramBot:  telegram.NewBotWithHandler(integration.NewTelegramHandler(store)),
	}

	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: `{"time":"${time_rfc3339}","latency":"${latency_human}",` +
			`"method":"${method}","uri":"${uri}",` +
			`"status":${status},"error":"${error}"}` + "\n",
	}))

	e.Use(middleware.Gzip())

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		Skipper:      grpcRequestSkipper,
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
	}))

	e.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Skipper: grpcRequestSkipper,
		Timeout: 30 * time.Second,
	}))

	// ######## CONNECT START
	e.Use(connect.Create(os.Getenv("SECRET_KEY")))
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if connectUser, err := connect.GetUser(c); err == nil {
				ctx := c.Request().Context()
				user, err := s.Store.GetUser(ctx, &storeX.FindUser{
					Email: &connectUser.Email,
				})
				if user == nil || err != nil {
					role := storeX.RoleUser
					// if connectUser.Role == "ADMIN" {
					// 	role = storeX.RoleHost
					// }
					if os.Getenv("ADMIN_EMAIL") == connectUser.Email {
						role = storeX.RoleHost
					}

					user, err = s.Store.CreateUser(ctx, &storeX.User{
						Nickname:     connectUser.Nickname,
						AvatarURL:    connectUser.Avatar,
						Email:        connectUser.Email,
						Username:     connectUser.Email,
						Role:         role,
						PasswordHash: random.String(32),
					})

					logger.Infof("[connect] create user: %s(email: %s)", connectUser.Nickname, connectUser.Email)
				} else if user.Role != storeX.RoleHost && os.Getenv("ADMIN_EMAIL") == connectUser.Email {
					user.Role = storeX.RoleHost
					user, err = s.Store.UpdateUser(ctx, &storeX.UpdateUser{
						ID:   user.ID,
						Role: &user.Role,
					})
				}

				logger.Infof("[connect] login user: %s(email: %s)", connectUser.Nickname, connectUser.Email)
				accessToken, err := auth.GenerateAccessToken(user.Username, user.ID, time.Now().Add(auth.AccessTokenDuration), []byte(s.Secret))
				if err != nil {
					return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to generate tokens, err: %s", err)).SetInternal(err)
				}

				if err := s.apiV1Service.UpsertAccessTokenToStore(ctx, user, accessToken); err != nil {
					return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to upsert access token, err: %s", err)).SetInternal(err)
				}
				if err := s.apiV1Service.CreateAuthSignInActivity(c, user); err != nil {
					return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create activity").SetInternal(err)
				}
				cookieExp := time.Now().Add(auth.CookieExpDuration)

				// setTokenCookie sets the token to the cookie.
				setTokenCookie := func(name, token string, expiration time.Time) {
					cookie := new(http.Cookie)
					cookie.Name = name
					cookie.Value = token
					cookie.Expires = expiration
					cookie.Path = "/"
					// Http-only helps mitigate the risk of client side script accessing the protected cookie.
					cookie.HttpOnly = true
					cookie.SameSite = http.SameSiteStrictMode
					c.SetCookie(cookie)
				}

				setTokenCookie(auth.AccessTokenCookieName, accessToken, cookieExp)

				// @TODO api.userIDContextKey not exported.
				// c.Set("user-id", user.ID)
			}

			return next(c)
		}
	})
	// ######## CONNECT END

	serverID, err := s.getSystemServerID(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to retrieve system server ID")
	}
	s.ID = serverID

	// Serve frontend.
	embedFrontend(e)

	// Serve swagger in dev/demo mode.
	if profile.Mode == "dev" || profile.Mode == "demo" {
		e.GET("/api/*", echoSwagger.WrapHandler)
	}

	secret := "usememos"
	if profile.Mode == "prod" {
		secret, err = s.getSystemSecretSessionName(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to retrieve system secret session name")
		}
	}
	s.Secret = secret

	rootGroup := e.Group("")
	apiV1Service := apiv1.NewAPIV1Service(s.Secret, profile, store, s.telegramBot)
	apiV1Service.Register(rootGroup)

	s.apiV1Service = apiV1Service

	s.apiV2Service = apiv2.NewAPIV2Service(s.Secret, profile, store, s.Profile.Port+1)
	// Register gRPC gateway as api v2.
	if err := s.apiV2Service.RegisterGateway(ctx, e); err != nil {
		return nil, errors.Wrap(err, "failed to register gRPC gateway")
	}

	return s, nil
}

func (s *Server) Start(ctx context.Context) error {
	if err := s.createServerStartActivity(ctx); err != nil {
		return errors.Wrap(err, "failed to create activity")
	}

	go s.telegramBot.Start(ctx)
	go s.backupRunner.Run(ctx)

	// Start gRPC server.
	listen, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.Profile.Addr, s.Profile.Port+1))
	if err != nil {
		return err
	}
	go func() {
		if err := s.apiV2Service.GetGRPCServer().Serve(listen); err != nil {
			log.Error("grpc server listen error", zap.Error(err))
		}
	}()

	return s.e.Start(fmt.Sprintf("%s:%d", s.Profile.Addr, s.Profile.Port))
}

func (s *Server) Shutdown(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Shutdown echo server
	if err := s.e.Shutdown(ctx); err != nil {
		fmt.Printf("failed to shutdown server, error: %v\n", err)
	}

	// Close database connection
	if err := s.Store.Close(); err != nil {
		fmt.Printf("failed to close database, error: %v\n", err)
	}

	fmt.Printf("memos stopped properly\n")
}

func (s *Server) GetEcho() *echo.Echo {
	return s.e
}

func (s *Server) getSystemServerID(ctx context.Context) (string, error) {
	serverIDSetting, err := s.Store.GetSystemSetting(ctx, &store.FindSystemSetting{
		Name: apiv1.SystemSettingServerIDName.String(),
	})
	if err != nil {
		return "", err
	}
	if serverIDSetting == nil || serverIDSetting.Value == "" {
		serverIDSetting, err = s.Store.UpsertSystemSetting(ctx, &store.SystemSetting{
			Name:  apiv1.SystemSettingServerIDName.String(),
			Value: uuid.NewString(),
		})
		if err != nil {
			return "", err
		}
	}
	return serverIDSetting.Value, nil
}

func (s *Server) getSystemSecretSessionName(ctx context.Context) (string, error) {
	secretSessionNameValue, err := s.Store.GetSystemSetting(ctx, &store.FindSystemSetting{
		Name: apiv1.SystemSettingSecretSessionName.String(),
	})
	if err != nil {
		return "", err
	}
	if secretSessionNameValue == nil || secretSessionNameValue.Value == "" {
		secretSessionNameValue, err = s.Store.UpsertSystemSetting(ctx, &store.SystemSetting{
			Name:  apiv1.SystemSettingSecretSessionName.String(),
			Value: uuid.NewString(),
		})
		if err != nil {
			return "", err
		}
	}
	return secretSessionNameValue.Value, nil
}

func (s *Server) createServerStartActivity(ctx context.Context) error {
	payload := apiv1.ActivityServerStartPayload{
		ServerID: s.ID,
		Profile:  s.Profile,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrap(err, "failed to marshal activity payload")
	}
	activity, err := s.Store.CreateActivity(ctx, &store.Activity{
		Type:    apiv1.ActivityServerStart.String(),
		Level:   apiv1.ActivityInfo.String(),
		Payload: string(payloadBytes),
	})
	if err != nil || activity == nil {
		return errors.Wrap(err, "failed to create activity")
	}
	return err
}

func grpcRequestSkipper(c echo.Context) bool {
	return strings.HasPrefix(c.Request().URL.Path, "/memos.api.v2.")
}
