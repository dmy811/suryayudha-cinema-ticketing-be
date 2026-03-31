# 🎬 surya-yudha-e-ticket-cinema-booking-backend

> Backend REST API for the **Surya Yudha Cinema** e-ticket booking application — enabling users to browse movies, select showtimes, choose seats, and purchase tickets online.

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Tech Stack](#-tech-stack)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Environment Variables](#environment-variables)
  - [Installation](#installation)
  - [Running the App](#running-the-app)
- [Database](#-database)
- [API Documentation](#-api-documentation)
- [Authentication Flow](#-authentication-flow)
- [Payment Flow](#-payment-flow)
- [Testing](#-testing)
- [Scripts Reference](#-scripts-reference)
- [License](#-license)

---

## 🧭 Overview

`surya-yudha-e-ticket-cinema-booking-backend` is a production-ready REST API built with **Node.js**, **Express**, and **PostgreSQL**. It powers the full lifecycle of a cinema booking system — from browsing movies and scheduling showtime seats, to processing payments via Midtrans and generating e-tickets.

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js |
| Framework | Express.js v5 |
| Language | TypeScript |
| Database | PostgreSQL |
| ORM | Prisma |
| Cache / Session | Redis (ioredis) |
| Rate limit | Redis (rate-limiter-flexible) |
| Hashing | Argon2 |
| Authentication | JWT (RS256), Passport.js |
| OAuth | Google OAuth 2.0, Facebook OAuth |
| Payment Gateway | Midtrans |
| File Upload | ImageKit |
| Email | Nodemailer |
| Validation | Zod |
| Logging | Winston + Daily Rotate File |
| Task Scheduler | node-cron |
| Containerization | Docker |
| Testing | Vitest + Supertest |
| API Docs | Swagger UI (OpenAPI 3.0) |

---

## ✨ Features

### 🔐 Authentication & Authorization
- Local registration with email verification
- Login for users and admins (separate endpoints)
- Google OAuth 2.0 & Facebook OAuth login
- JWT-based authentication using RS256 (asymmetric keys)
- Access token + refresh token rotation
- Forgot password & reset password via email
- Change password & update profile

### 🎥 Movie Management
- CRUD movies with status: `coming_soon`, `now_showing`, `ended`
- Filter movies by status, title, or genre
- Manage movie genres and cast members
- Associate multiple genres to a movie

### 🏢 Studio & Seat Management
- CRUD studios with screen placement (`top`, `left`, `right`)
- Multiple gallery photos per studio (ImageKit)
- Auto-generate seats when studio is created
- Seat status management per schedule: `available`, `booked`, `reserved`

### 📅 Schedule Management
- Create schedules with movie, studio, start time, and price
- Auto-calculate `finished_time` based on movie duration
- View available seats per schedule in real time

### 🎟 Booking & Transaction
- Book seats and initiate transactions
- Booking expires automatically (node-cron)
- Apply voucher codes (percentage or fixed discount)
- Payment via Midtrans (Snap)
- Webhook handler for Midtrans payment notifications
- Check live payment status from Midtrans

### 🧾 E-Ticket
- Unique ticket code generated per seat upon payment settlement
- Ticket statuses: `active`, `used`, `expired`, `cancelled`
- Admin ticket validation by code
- View personal tickets (user)

### 🔔 Notifications
- Admin can broadcast notifications to `all` users or `specific` user
- Users can mark notifications as read or hide them

### 🧮 Admin Dashboard
- Stats overview (users, movies, revenue, transactions)
- Chart data for analytics

### 🔑 Voucher Management
- CRUD vouchers (percentage / fixed discount)
- Usage limit, expiry date, minimum purchase amount

---

## 📁 Project Structure

```
test/                       # Unit test, Integration test, and E2E test (Not completed yet)
src/
├── docs/                   # OpenAPI YAML documentation (Not completed yet)
├── applications/           # App building
│   ├──routes/              # App Routes
│   ├──modules/
│       ├── auth/           # Auth routes, controllers, services, validation
│       ├── movie/
│       ├── cast/
│       ├── genre/
│       ├── studio/
│       ├── schedule/
│       ├── transaction/
│       ├── ticket/
│       ├── voucher/
│       ├── notification/
│       ├── user/
│       └── dashboard/
│       └── webhook/
├── infrastructure/
│   ├── database/
│   │   ├── prisma/         # Prisma schema & migrations
│   │   └── seed.ts         # Database seeder
│   └── cache/              # Caching strategy
│   └── config/             # System configuration
│   └── cron-jobs/          # Schedulers
│   └── factories/          # Dependency Injection
│   └── repositories/       # Repositories layer
│   └── types/              # Project type/interface
├── shared/                 # Shared utilities
│   └── error-handling/     # Error handling
│   └── helpers/            # Helpers
│   └── logger/             # Logger 
│   └── middlewares/        # Middlewares
└── server/
    └── index.ts            # App entry point
```

---

## 🚀 Getting Started

### Prerequisites

Make sure you have the following installed:

- [Node.js](https://nodejs.org/) >= 18.x
- [pnpm](https://pnpm.io/) >= 10.x
- [PostgreSQL](https://www.postgresql.org/) >= 14
- [Redis](https://redis.io/) >= 7
- [Docker](https://www.docker.com/) *(optional, recommended)*

---

### Environment Variables

Create a `.env` file in the root directory. Use `.env.example` as a reference:

```env
# App
PORT=5000
CORS_ORIGIN=

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/surya_yudha_cinema

# Redis
REDIS_PORT=
REDIS_HOST=
REDIS_PASSWORD=

# JWT (Base64 encoded RSA keys)
ACCESS_TOKEN_PRIVATE_KEY=<base64_encoded_private_key>
ACCESS_TOKEN_PUBLIC_KEY=<base64_encoded_public_key>
REFRESH_TOKEN_PRIVATE_KEY=<base64_encoded_private_key>
REFRESH_TOKEN_PUBLIC_KEY=<base64_encoded_public_key>

# Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_CALLBACK_URL=http://localhost:5000/api/v1/auth/google/callback

# Facebook OAuth
FACEBOOK_CLIENT_ID=your_facebook_app_id
FACEBOOK_CLIENT_SECRET=your_facebook_app_secret
FACEBOOK_CALLBACK_URL=http://localhost:5000/api/v1/auth/facebook/callback

# Nodemailer
USER_EMAIL=your_email@gmail.com
APP_PASSWORD=your_app_password

# Midtrans
MIDTRANS_SERVER_KEY=your_midtrans_server_key
MIDTRANS_CLIENT_KEY=your_midtrans_client_key

# ImageKit
IMAGEKIT_PUBLIC_KEY=your_imagekit_public_key
IMAGEKIT_PRIVATE_KEY=your_imagekit_private_key
IMAGEKIT_URL_ENDPOINT=https://ik.imagekit.io/your_id
```

---

### Generate RSA Keys

JWT authentication uses RS256 (asymmetric). Generate the required key pairs:

```bash
# Access Token keys
pnpm gen:private:accesstoken
pnpm gen:public:accesstoken
pnpm gen:private:accesstoken:b64
pnpm gen:public:accesstoken:b64

# Refresh Token keys
pnpm gen:private:refreshtoken:b64
pnpm gen:public:refreshtoken:b64
```

Copy the `.b64` values into your `.env` file.

---

### Installation

```bash
# Clone the repository
git clone https://github.com/dmy811/suryayudha-cinema-ticketing-be.git
cd suryayudha-cinema-ticketing-be

# Install dependencies
pnpm install

# Generate Prisma client
pnpm prisma:generate:dev

# Run database migrations
pnpm prisma:migrate:dev

# (Optional) Seed the database
pnpm prisma:seed:dev
```

---

### Running the App

**Development mode** (with hot-reload via nodemon):
```bash
pnpm dev
```

**Build & run production:**
```bash
pnpm build
pnpm prod
```

**Using Docker:**
```bash
docker compose up -d
```

The API will be available at: `http://localhost:5000/api/v1`

---

## 🗄 Database

This project uses **PostgreSQL** with **Prisma ORM**.

### Entity Overview

| Model | Description |
|---|---|
| `User` | App users and admins |
| `Movie` | Movie catalog with status |
| `Cast` | Movie cast members |
| `Genre` | Movie genres (many-to-many) |
| `Studio` | Cinema studios with seat layout |
| `Seat` | Individual seats per studio |
| `Schedule` | Showtimes linking movie + studio |
| `ScheduleSeat` | Per-schedule seat availability |
| `Transaction` | Booking/payment records |
| `TransactionItem` | Seats within a transaction |
| `Ticket` | Generated e-tickets with unique code |
| `Voucher` | Discount vouchers (% or fixed) |
| `Notification` | Broadcast notifications |

### Useful Prisma Commands

```bash
# Open Prisma Studio (GUI)
pnpm prisma:studio:dev

# Create new migration
pnpm prisma:migrate:dev

# Deploy migrations (staging/production)
pnpm prisma:migrate:prod
```

---

## 📖 API Documentation

Interactive Swagger UI is available at:

```
http://localhost:5000/api/v1/docs
```

### Base URL

```
/api/v1/
```

### Endpoint Summary

<details>
<summary><strong>🔐 Auth</strong></summary>

| Method | Endpoint | Role | Description |
|---|---|---|---|
| POST | `/auth/register` | Public | Register new user |
| POST | `/auth/login` | Public | User login |
| POST | `/auth/login-admin` | Public | Admin login |
| POST | `/auth/refresh` | User & Admin | Refresh access token |
| GET | `/auth/google` | Public | Google OAuth redirect |
| GET | `/auth/google/callback` | Public | Google OAuth callback |
| GET | `/auth/facebook` | Public | Facebook OAuth redirect |
| GET | `/auth/facebook/callback` | Public | Facebook OAuth callback |
| GET | `/auth/verify-email` | Public | Verify email address |
| GET | `/auth/resend-verification-token` | Public | Resend verification email |
| GET | `/auth/profile` | User & Admin | Get own profile |
| PATCH | `/auth/update-profile` | User & Admin | Update profile |
| PATCH | `/auth/change-password` | User & Admin | Change password |
| POST | `/auth/forgot-password` | Public | Request password reset |
| POST | `/auth/reset-password` | Public | Reset password with code |
| GET | `/auth/check-auth` | User | Check auth status |
| POST | `/auth/logout` | User & Admin | Logout |

</details>

<details>
<summary><strong>🎥 Movies</strong></summary>

| Method | Endpoint | Role | Description |
|---|---|---|---|
| GET | `/movies` | Public | List movies (filter by status, title, genre) |
| GET | `/movies/:id` | Public | Get movie detail |
| POST | `/movies` | Admin | Create movie |
| PATCH | `/movies/:id` | Admin | Update movie |
| DELETE | `/movies/:id` | Admin | Delete movie |

</details>

<details>
<summary><strong>📅 Schedules & Seats</strong></summary>

| Method | Endpoint | Role | Description |
|---|---|---|---|
| GET | `/schedules` | Public | List all schedules |
| GET | `/schedules/:id` | Public | Get schedule detail |
| POST | `/schedules` | Admin | Create schedule |
| DELETE | `/schedules/:id` | Admin | Delete schedule |
| GET | `/schedules/:id/seats` | Public | Get available seats |
| PATCH | `/schedules/seats/:id` | Admin | Update seat status |

</details>

<details>
<summary><strong>🎟 Transactions & Tickets</strong></summary>

| Method | Endpoint | Role | Description |
|---|---|---|---|
| POST | `/transactions` | User & Admin | Create booking transaction |
| GET | `/transactions/my` | User & Admin | Get own transactions |
| GET | `/transactions/:id` | User & Admin | Get transaction detail |
| POST | `/transactions/:id/pay` | User & Admin | Initiate payment (Midtrans) |
| PATCH | `/vouchers/:transactionId/apply` | User & Admin | Apply voucher |
| POST | `/webhooks/midtrans` | Midtrans | Payment webhook |
| GET | `/transactions/check-status/:orderId` | Admin | Check Midtrans status |
| GET | `/tickets/my` | User & Admin | Get own tickets |
| GET | `/tickets/:id` | User & Admin | Get ticket detail |
| PATCH | `/tickets/validate` | Admin | Validate ticket by code |

</details>

---

## 🔐 Authentication Flow

```
User registers → Email verification sent → User verifies email
     ↓
User logs in → Access Token (15m) + Refresh Token (7d) returned
     ↓
Access Token expires → POST /auth/refresh → New Access Token issued
     ↓
User logs out → Refresh Token invalidated (Redis blacklist)
```

**Token Strategy:**
- Access Token: RS256 JWT, short-lived (15 minutes)
- Refresh Token: RS256 JWT, long-lived (7 days), stored in HTTP-only cookie
- Token blacklist managed via **Redis**

---

## 💳 Payment Flow

```
User selects seats → POST /transactions (status: initiated, booking_expires_at set)
     ↓
User applies voucher (optional) → PATCH vouchers/:transactionId/apply
     ↓
User initiates payment → POST /transactions/:id/pay
     → Midtrans Snap URL returned (status: pending)
     ↓
User completes payment on Midtrans
     ↓
Midtrans sends webhook → POST /webhooks/midtrans
     → status updated to: settlement / cancelled
     → E-tickets generated with unique codes (on settlement)
     ↓
User views tickets → GET /tickets/my
     ↓
Admin scans & validates ticket → PATCH /tickets/validate
```

**Booking Expiry:** If a user doesn't proceed to payment within the booking window, a **node-cron** job automatically releases the reserved seats and cancels the transaction.

---

## 🧪 Testing

This project uses **Vitest** + **Supertest** for unit and integration testing.

```bash
# Run all tests once
pnpm test

# Run tests in watch mode
pnpm test:watch

# Run with coverage report
pnpm test

# Run tests for CI (JUnit + JSON reports)
pnpm test:ci

# Open Vitest UI
pnpm test:ui
```

Tests are run against a **separate test database** (`NODE_ENV=test`) defined in your `.env.test` file.  (*the testing not all done)

---

## 📜 Scripts Reference

| Script | Description |
|---|---|
| `pnpm dev` | Start development server with hot-reload |
| `pnpm build` | Compile TypeScript to JavaScript |
| `pnpm prod` | Start production server |
| `pnpm test` | Run all tests with coverage |
| `pnpm format` | Format code with Prettier |
| `pnpm check-types` | TypeScript type checking |
| `pnpm prisma:migrate:dev` | Run DB migrations (dev) |
| `pnpm prisma:studio:dev` | Open Prisma Studio GUI |
| `pnpm prisma:seed:dev` | Seed development database |
| `pnpm validate:yaml` | Validate OpenAPI YAML spec |

---

#### Database Diagram

![diagram](./public/img/cinema-booking.png)
