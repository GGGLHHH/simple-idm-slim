package idm_test

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/tendant/simple-idm-slim/idm"
)

func Example_basic() {
	// Connect to your database
	db, err := sql.Open("postgres", "postgres://localhost/myapp?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	// Create IDM instance
	auth, err := idm.New(idm.Config{
		DB:        db,
		JWTSecret: "your-secret-key-at-least-32-characters",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Mount auth routes under /auth/
	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))

	fmt.Println("Server starting on :8080")
	// http.ListenAndServe(":8080", mux)
}

func Example_withRoutes() {
	db, _ := sql.Open("postgres", "postgres://localhost/myapp?sslmode=disable")

	auth, err := idm.New(idm.Config{
		DB:        db,
		JWTSecret: "your-secret-key-at-least-32-characters",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Use Routes() to register with custom prefix
	mux := http.NewServeMux()
	auth.Routes(mux, "/api/v1/auth")

	// Routes are now:
	// POST /api/v1/auth/register
	// POST /api/v1/auth/login
	// etc.

	fmt.Println("Server starting on :8080")
}

func Example_withChiRouter() {
	db, _ := sql.Open("postgres", "postgres://localhost/myapp?sslmode=disable")

	auth, err := idm.New(idm.Config{
		DB:        db,
		JWTSecret: "your-secret-key-at-least-32-characters",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Use chi router directly
	r := chi.NewRouter()

	// Mount auth routes under /auth
	r.Mount("/auth", auth.Router())

	// Or mount auth and me separately
	r.Mount("/api/auth", auth.AuthRouter())
	r.Mount("/api/user", auth.MeRouter())

	fmt.Println("Server with chi router starting on :8080")
	// http.ListenAndServe(":8080", r)
}

func Example_separateMeEndpoint() {
	db, _ := sql.Open("postgres", "postgres://localhost/myapp?sslmode=disable")

	auth, _ := idm.New(idm.Config{
		DB:        db,
		JWTSecret: "your-secret-key-at-least-32-characters",
	})

	mux := http.NewServeMux()

	// Mount auth routes (without /me)
	mux.HandleFunc("POST /auth/register", nil) // from auth.Handler()
	mux.HandleFunc("POST /auth/login", nil)    // from auth.Handler()

	// Mount /me separately wherever you want
	mux.Handle("/user/profile", auth.MeHandler())
	// or
	mux.Handle("/api/me", auth.MeHandler())

	fmt.Println("Me endpoint mounted separately")
}

func Example_protectCustomRoutes() {
	db, _ := sql.Open("postgres", "postgres://localhost/myapp?sslmode=disable")

	auth, _ := idm.New(idm.Config{
		DB:        db,
		JWTSecret: "your-secret-key-at-least-32-characters",
	})

	mux := http.NewServeMux()

	// Mount auth routes
	auth.Routes(mux, "/auth")

	// Protect your own routes
	mux.Handle("/api/", auth.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user ID
		userID, ok := idm.GetUserID(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Or get full user info
		user, err := auth.GetUser(r)
		if err != nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}

		fmt.Fprintf(w, "Hello %s (%s)!", *user.Name, userID)
	})))

	fmt.Println("Protected routes configured")
}

func Example_protectWithChi() {
	db, _ := sql.Open("postgres", "postgres://localhost/myapp?sslmode=disable")

	auth, _ := idm.New(idm.Config{
		DB:        db,
		JWTSecret: "your-secret-key-at-least-32-characters",
	})

	r := chi.NewRouter()

	// Mount auth routes
	r.Mount("/auth", auth.Router())

	// Protected API routes using chi's Group
	r.Group(func(r chi.Router) {
		r.Use(auth.AuthMiddleware())

		r.Get("/api/profile", func(w http.ResponseWriter, r *http.Request) {
			user, _ := auth.GetUser(r)
			fmt.Fprintf(w, "Hello %s!", user.Email)
		})

		r.Get("/api/data", func(w http.ResponseWriter, r *http.Request) {
			userID, _ := idm.GetUserID(r)
			fmt.Fprintf(w, "Data for user %s", userID)
		})
	})

	fmt.Println("Protected chi routes configured")
}

func Example_withGoogle() {
	db, _ := sql.Open("postgres", "postgres://localhost/myapp?sslmode=disable")

	auth, err := idm.New(idm.Config{
		DB:        db,
		JWTSecret: "your-secret-key-at-least-32-characters",
		Google: &idm.GoogleConfig{
			ClientID:     "your-google-client-id",
			ClientSecret: "your-google-client-secret",
			RedirectURI:  "http://localhost:8080/auth/google/callback",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))

	fmt.Println("Server with Google OAuth starting on :8080")
}
