package idm_test

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/tendant/simple-idm-slim/idm"
)

func Example() {
	// Connect to database (migrations must be run first)
	db, err := sql.Open("postgres", "postgres://localhost/myapp?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	// Create IDM instance (validates schema exists)
	auth, err := idm.New(idm.Config{
		DB:        db,
		JWTSecret: "your-secret-key-at-least-32-characters",
	})
	if err != nil {
		log.Fatal(err) // Fails if migrations haven't been run
	}

	// Mount on chi router
	r := chi.NewRouter()
	r.Mount("/auth", auth.Router())

	fmt.Println("Server starting on :8080")
	// http.ListenAndServe(":8080", r)
}

func Example_withStdlib() {
	db, _ := sql.Open("postgres", "postgres://localhost/myapp?sslmode=disable")

	auth, _ := idm.New(idm.Config{
		DB:        db,
		JWTSecret: "your-secret-key-at-least-32-characters",
	})

	// Use with standard library
	mux := http.NewServeMux()
	auth.Routes(mux, "/api/v1/auth")

	fmt.Println("Server with stdlib starting on :8080")
}

func Example_protectRoutes() {
	db, _ := sql.Open("postgres", "postgres://localhost/myapp?sslmode=disable")

	auth, _ := idm.New(idm.Config{
		DB:        db,
		JWTSecret: "your-secret-key-at-least-32-characters",
	})

	r := chi.NewRouter()
	r.Mount("/auth", auth.Router())

	// Protected routes using chi's Group
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

	fmt.Println("Protected routes configured")
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

	r := chi.NewRouter()
	r.Mount("/auth", auth.Router())

	fmt.Println("Server with Google OAuth starting on :8080")
}
