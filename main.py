"""
main.py  —  Supermarket Deals API v2
FastAPI backend for the Bulgarian supermarket deals Android app.

Endpoints:
  POST /register              — create account
  POST /login                 — login, get JWT token
  PUT  /me/city               — update user city
  GET  /home                  — 10 products per category (city-filtered)
  GET  /categories            — list all categories with product counts
  GET  /categories/{name}     — paginated products in a category
  GET  /search?q=             — full-text + trigram search
  GET  /product/{id}          — product detail with all store prices
  GET  /stores                — stores available in a city
  POST /alerts                — subscribe to price alert
  DELETE /alerts              — unsubscribe
  GET  /health                — health check

Install:
    pip install fastapi uvicorn psycopg2-binary python-dotenv passlib[bcrypt] python-jose[cryptography]

Run:
    uvicorn main:app --reload --port 8000
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import psycopg2
import psycopg2.extras
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import psycopg2.pool
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
import bcrypt as _bcrypt
from pydantic import BaseModel, EmailStr

load_dotenv()

# ── CONFIG ────────────────────────────────────────────────────────────────────

SECRET_KEY         = os.getenv("JWT_SECRET", "change-this-in-production-please")
ALGORITHM          = "HS256"
TOKEN_EXPIRE_DAYS  = 30


http_bearer = HTTPBearer(auto_error=False)

CATEGORIES = [
    "Месо и риба",
    "Мляко и млечни",
    "Плодове и зеленчуци",
    "Хляб и тестени",
    "Напитки",
    "Алкохол",
    "Сладкиши и снакс",
    "Замразени",
    "Домакинство и козметика",
    "Консерви и основни",
    "Бебешки продукти",
    "Здравословни храни",
    "Грижа за домашни любимци",
    "Техника",
    "Друго",
]

# ── APP ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="Supermarket Deals API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── DATABASE ──────────────────────────────────────────────────────────────────

def _build_dsn() -> dict:
    """Build the database connection kwargs from env vars."""
    from urllib.parse import urlparse, unquote
    url = os.getenv("DATABASE_URL", "")
    if url:
        url = url.replace("postgres://", "postgresql://", 1)
        parsed = urlparse(url)
        return dict(
            host=parsed.hostname,
            port=parsed.port or 5432,
            dbname=parsed.path.lstrip("/"),
            user=unquote(parsed.username or ""),
            password=unquote(parsed.password or ""),
        )
    return dict(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        dbname=os.getenv("DB_NAME", "supermarket_deals"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
    )

def get_db():
    """Get a database connection. Retries once on failure (handles cold starts)."""
    kwargs = _build_dsn()
    for attempt in range(2):
        try:
            return psycopg2.connect(
                cursor_factory=psycopg2.extras.RealDictCursor,
                connect_timeout=10,
                **kwargs,
            )
        except psycopg2.OperationalError:
            if attempt == 0:
                import time
                time.sleep(2)
            else:
                raise

# ── AUTH HELPERS ──────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())

def create_token(user_id: int, email: str) -> str:
    payload = {
        "sub":   str(user_id),
        "email": email,
        "exp":   datetime.now(timezone.utc) + timedelta(days=TOKEN_EXPIRE_DAYS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return {"id": int(payload["sub"]), "email": payload["email"]}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def get_optional_user(
    credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
) -> Optional[dict]:
    if not credentials:
        return None
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return {"id": int(payload["sub"]), "email": payload["email"]}
    except JWTError:
        return None

# ── PYDANTIC MODELS ───────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    city: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AlertCreate(BaseModel):
    product_id: int
    fcm_token: str

class AlertDelete(BaseModel):
    product_id: int
    fcm_token: str

class UpdateCityRequest(BaseModel):
    city: str

class UpdateNotificationPrefsRequest(BaseModel):
    notify_email: bool
    notify_push: bool
    fcm_token: Optional[str] = None

# ── SHARED HELPERS ────────────────────────────────────────────────────────────

def get_available_stores(cur, city: str) -> list[str]:
    cur.execute(
        "SELECT name FROM stores WHERE nationwide = TRUE OR %s = ANY(cities) ORDER BY name",
        (city,),
    )
    return [row["name"] for row in cur.fetchall()]

def format_offer(o) -> dict:
    return {
        "store":              o["store"],
        "price_eur":          float(o["price_eur"]) if o["price_eur"] else None,
        "original_price_eur": float(o["original_price_eur"]) if o["original_price_eur"] else None,
        "discount_pct":       o["discount_pct"],
        "valid_from":         o["valid_from"],
        "valid_to":           o["valid_to"],
        "image_url":          o.get("image_url", ""),
    }

def fetch_offers(cur, product_ids: list[int], stores: list[str]) -> dict:
    if not product_ids:
        return {}
    cur.execute(
        """
        SELECT product_id, store, price_eur, original_price_eur,
               discount_pct, valid_from, valid_to, image_url
        FROM store_offers
        WHERE product_id = ANY(%s) AND is_active = TRUE AND store = ANY(%s)
        ORDER BY product_id, discount_pct DESC NULLS LAST, price_eur ASC
        """,
        (product_ids, stores),
    )
    grouped: dict[int, list] = {}
    for o in cur.fetchall():
        grouped.setdefault(o["product_id"], []).append(format_offer(o))
    return grouped

def product_card(product, offers: list[dict]) -> dict:
    prices    = [o["price_eur"] for o in offers if o["price_eur"]]
    discounts = [o["discount_pct"] for o in offers if o["discount_pct"]]
    return {
        "id":                product["id"],
        "name":              product["name"],
        "category":          product.get("category", "Друго"),
        "image_url":         product.get("image_url", ""),
        "best_price_eur":    min(prices) if prices else None,
        "best_discount_pct": max(discounts) if discounts else None,
        "offers":            offers,
    }

def get_user_city(cur, user_id: int) -> str:
    cur.execute("SELECT city FROM users WHERE id = %s", (user_id,))
    row = cur.fetchone()
    return row["city"] if row else ""

def get_city_for_request(cur, user, request) -> str:
    """Get city from logged-in user or guest header."""
    if user:
        return get_user_city(cur, user["id"])
    # Guest mode — city passed in header
    return request.headers.get("X-Guest-City", "София")

# ── AUTH ENDPOINTS ────────────────────────────────────────────────────────────

@app.post("/register", status_code=201)
def register(req: RegisterRequest):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (req.email,))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="Email already registered")
        if len(req.password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        cur.execute(
            "INSERT INTO users (email, password_hash, city) VALUES (%s, %s, %s) RETURNING id",
            (req.email, hash_password(req.password), req.city),
        )
        user_id = cur.fetchone()["id"]
        conn.commit()
        return {
            "token": create_token(user_id, req.email),
            "user":  {"id": user_id, "email": req.email, "city": req.city},
        }
    finally:
        conn.close()


@app.post("/login")
def login(req: LoginRequest):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, password_hash, city FROM users WHERE email = %s",
            (req.email,),
        )
        user = cur.fetchone()
        if not user or not verify_password(req.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        return {
            "token": create_token(user["id"], user["email"]),
            "user":  {"id": user["id"], "email": user["email"], "city": user["city"]},
        }
    finally:
        conn.close()


@app.put("/me/city")
def update_city(req: UpdateCityRequest, user=Depends(get_current_user)):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET city = %s WHERE id = %s", (req.city, user["id"]))
        conn.commit()
        return {"message": "City updated", "city": req.city}
    finally:
        conn.close()


@app.get("/me")
def get_me(user=Depends(get_current_user)):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, city, notify_email, notify_push, fcm_token FROM users WHERE id = %s",
            (user["id"],)
        )
        u = cur.fetchone()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        return {
            "id": u["id"],
            "email": u["email"],
            "city": u["city"],
            "notify_email": u["notify_email"],
            "notify_push": u["notify_push"],
            "fcm_token": u["fcm_token"],
        }
    finally:
        conn.close()


@app.put("/me/notifications")
def update_notification_prefs(
    req: UpdateNotificationPrefsRequest,
    user=Depends(get_current_user)
):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """UPDATE users
               SET notify_email = %s, notify_push = %s, fcm_token = COALESCE(%s, fcm_token)
               WHERE id = %s""",
            (req.notify_email, req.notify_push, req.fcm_token, user["id"])
        )
        conn.commit()
        return {"message": "Notification preferences updated"}
    finally:
        conn.close()

# ── HOME ──────────────────────────────────────────────────────────────────────

@app.get("/home")
def home(
    request: Request,
    stores: Optional[str] = Query(None, description="Comma-separated store names, e.g. Kaufland,Lidl,Billa"),
    user=Depends(get_optional_user),
):
    """10 best-discount products per category, filtered to user's city stores
    and optionally to specific store names."""
    conn = get_db()
    try:
        cur = conn.cursor()
        city = get_city_for_request(cur, user, request)
        available = get_available_stores(cur, city)
        if not available:
            return {"city": city, "categories": []}

        # If store filter provided, intersect with available stores
        if stores:
            requested = [s.strip() for s in stores.split(",") if s.strip()]
            filtered = [s for s in requested if s in available]
        else:
            filtered = available

        if not filtered:
            return {"city": city, "available_stores": available, "categories": []}

        result = []
        for category in CATEGORIES:
            cur.execute(
                """
                SELECT p.id, p.name, p.category, p.image_url
                FROM products p
                WHERE p.category = %s
                  AND EXISTS (
                    SELECT 1 FROM store_offers so
                    WHERE so.product_id = p.id
                      AND so.is_active = TRUE
                      AND so.store = ANY(%s)
                  )
                ORDER BY (
                    SELECT MAX(so.discount_pct)
                    FROM store_offers so
                    WHERE so.product_id = p.id AND so.is_active = TRUE
                ) DESC NULLS LAST
                LIMIT 10
                """,
                (category, filtered),
            )
            products = cur.fetchall()
            pids = [p["id"] for p in products]
            offers_map = fetch_offers(cur, pids, filtered)
            cards = [
                product_card(dict(p), offers_map.get(p["id"], []))
                for p in products
                if offers_map.get(p["id"])
            ]
            cards.sort(key=lambda x: x["best_discount_pct"] or 0, reverse=True)
            result.append({"category": category, "products": cards})
        return {"city": city, "available_stores": available, "categories": result}
    finally:
        conn.close()

# ── CATEGORIES ────────────────────────────────────────────────────────────────

@app.get("/categories")
def list_categories(request: Request, user=Depends(get_optional_user)):
    conn = get_db()
    try:
        cur    = conn.cursor()
        city   = get_city_for_request(cur, user, request)
        stores = get_available_stores(cur, city)

        result = []
        for category in CATEGORIES:
            cur.execute(
                """
                SELECT COUNT(DISTINCT p.id)
                FROM products p
                JOIN store_offers so ON so.product_id = p.id
                WHERE p.category = %s AND so.is_active = TRUE AND so.store = ANY(%s)
                """,
                (category, stores),
            )
            count = cur.fetchone()["count"]
            result.append({"name": category, "product_count": count})

        return {"categories": result}
    finally:
        conn.close()


@app.get("/categories/{category_name}")
def get_category(
    category_name: str,
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user=Depends(get_optional_user),
):
    if category_name not in CATEGORIES:
        raise HTTPException(status_code=404, detail="Category not found")

    conn = get_db()
    try:
        cur    = conn.cursor()
        city   = get_city_for_request(cur, user, request)
        stores = get_available_stores(cur, city)
        offset = (page - 1) * page_size

        cur.execute(
            """
            SELECT COUNT(DISTINCT p.id)
            FROM products p
            JOIN store_offers so ON so.product_id = p.id
            WHERE p.category = %s AND so.is_active = TRUE AND so.store = ANY(%s)
            """,
            (category_name, stores),
        )
        total = cur.fetchone()["count"]

        cur.execute(
            """
            SELECT p.id, p.name, p.category, p.image_url
            FROM products p
            WHERE p.category = %s
              AND EXISTS (
                SELECT 1 FROM store_offers so
                WHERE so.product_id = p.id
                  AND so.is_active = TRUE
                  AND so.store = ANY(%s)
              )
            ORDER BY (
                SELECT MAX(so.discount_pct)
                FROM store_offers so
                WHERE so.product_id = p.id AND so.is_active = TRUE
            ) DESC NULLS LAST,
            (
                SELECT MIN(so.price_eur)
                FROM store_offers so
                WHERE so.product_id = p.id AND so.is_active = TRUE
            ) ASC
            LIMIT %s OFFSET %s
            """,
            (category_name, stores, page_size, offset),
        )
        products   = cur.fetchall()
        pids       = [p["id"] for p in products]
        offers_map = fetch_offers(cur, pids, stores)

        cards = [
            product_card(dict(p), offers_map.get(p["id"], []))
            for p in products
            if offers_map.get(p["id"])
        ]
        cards.sort(key=lambda x: x["best_discount_pct"] or 0, reverse=True)

        return {
            "category":    category_name,
            "page":        page,
            "page_size":   page_size,
            "total":       total,
            "total_pages": (total + page_size - 1) // page_size,
            "products":    cards,
        }
    finally:
        conn.close()

# ── SEARCH ────────────────────────────────────────────────────────────────────

@app.get("/search")
def search(
    q: str = Query(..., min_length=1),
    request: Request = None,
    limit: int = Query(50, ge=1, le=200),
    strict: bool = Query(True),
    stores: Optional[str] = Query(None, description="Comma-separated store names, e.g. Kaufland,Lidl,Billa"),
    user=Depends(get_optional_user),
):
    conn = get_db()
    try:
        cur    = conn.cursor()
        city   = get_city_for_request(cur, user, request)
        available = get_available_stores(cur, city)

        if stores:
            requested = [s.strip() for s in stores.split(",") if s.strip()]
            filtered = [s for s in requested if s in available]
        else:
            filtered = available

        if strict:
            words = q.strip().split()
            conditions = " AND ".join(["p.name ILIKE %s"] * len(words))
            like_params = [f"%{w}%" for w in words]
            cur.execute(
                f"""
                SELECT p.id, p.name, p.category, p.image_url
                FROM products p
                WHERE {conditions}
                ORDER BY p.name
                LIMIT %s
                """,
                like_params + [limit],
            )
        else:
            cur.execute(
                """
                SELECT p.id, p.name, p.category, p.image_url
                FROM products p
                WHERE p.name ILIKE %s
                   OR similarity(p.name, %s) > 0.3
                   OR to_tsvector('simple', p.name) @@ plainto_tsquery('simple', %s)
                ORDER BY similarity(p.name, %s) DESC, p.name
                LIMIT %s
                """,
                (f"%{q}%", q, q, q, limit),
            )
        products   = cur.fetchall()
        pids       = [p["id"] for p in products]
        offers_map = fetch_offers(cur, pids, filtered)
        results = [
            product_card(dict(p), offers_map.get(p["id"], []))
            for p in products
            if offers_map.get(p["id"])
        ]
        results.sort(key=lambda x: x["best_discount_pct"] or 0, reverse=True)
        return {"query": q, "count": len(results), "results": results}
    finally:
        conn.close()

# ── PRODUCT DETAIL ────────────────────────────────────────────────────────────

@app.get("/product/{product_id}")
def get_product(product_id: int, request: Request, user=Depends(get_optional_user)):
    conn = get_db()
    try:
        cur    = conn.cursor()
        city   = get_city_for_request(cur, user, request)
        stores = get_available_stores(cur, city)

        cur.execute(
            "SELECT id, name, category, description, image_url FROM products WHERE id = %s",
            (product_id,),
        )
        product = cur.fetchone()
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")

        offers_map = fetch_offers(cur, [product_id], stores)
        offers     = offers_map.get(product_id, [])

        if user:
            cur.execute(
                "SELECT id FROM alert_subscriptions WHERE product_id=%s AND user_id=%s AND is_active=TRUE",
                (product_id, user["id"]),
            )
            has_alert = cur.fetchone() is not None
        else:
            has_alert = False

        return {
            "id":          product["id"],
            "name":        product["name"],
            "category":    product["category"],
            "description": product["description"],
            "image_url":   product["image_url"],
            "offers":      offers,
            "has_alert":   has_alert,
        }
    finally:
        conn.close()

# ── STORES ────────────────────────────────────────────────────────────────────

@app.get("/stores")
def get_stores(
    city: Optional[str] = Query(None),
    user=Depends(get_optional_user),
):
    conn = get_db()
    try:
        cur = conn.cursor()
        if not city and user:
            city = get_user_city(cur, user["id"])
        city = city or ""

        cur.execute(
            """
            SELECT s.name, s.nationwide, s.cities,
                   COUNT(so.id) AS active_offers,
                   MAX(so.scraped_at) AS last_scraped
            FROM stores s
            LEFT JOIN store_offers so ON so.store = s.name AND so.is_active = TRUE
            WHERE s.nationwide = TRUE OR %s = ANY(s.cities)
            GROUP BY s.name, s.nationwide, s.cities
            ORDER BY s.name
            """,
            (city,),
        )
        return {
            "city": city,
            "stores": [
                {
                    "name":          s["name"],
                    "nationwide":    s["nationwide"],
                    "active_offers": s["active_offers"],
                    "last_scraped":  s["last_scraped"].isoformat() if s["last_scraped"] else None,
                }
                for s in cur.fetchall()
            ],
        }
    finally:
        conn.close()

# ── ALERTS ────────────────────────────────────────────────────────────────────

@app.post("/alerts", status_code=201)
def create_alert(alert: AlertCreate, user=Depends(get_current_user)):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM products WHERE id = %s", (alert.product_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Product not found")
        cur.execute(
            """
            INSERT INTO alert_subscriptions (product_id, fcm_token, user_id)
            VALUES (%s, %s, %s)
            ON CONFLICT (product_id, fcm_token) DO UPDATE
                SET is_active = TRUE, created_at = NOW(), user_id = EXCLUDED.user_id
            """,
            (alert.product_id, alert.fcm_token, user["id"]),
        )
        conn.commit()
        return {"message": "Alert created", "product_id": alert.product_id}
    finally:
        conn.close()


@app.delete("/alerts")
def delete_alert(alert: AlertDelete, user=Depends(get_current_user)):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE alert_subscriptions SET is_active=FALSE WHERE product_id=%s AND fcm_token=%s AND user_id=%s",
            (alert.product_id, alert.fcm_token, user["id"]),
        )
        conn.commit()
        return {"message": "Alert removed"}
    finally:
        conn.close()

# ── HEALTH ────────────────────────────────────────────────────────────────────

@app.get("/alerts")
def get_alerts(user=Depends(get_current_user)):
    """Get all active alert subscriptions for the current user."""
    conn = get_db()
    try:
        cur = conn.cursor()
        city   = get_city_for_request(cur, user, request)
        stores = get_available_stores(cur, city)

        cur.execute(
            """
            SELECT
                a.id AS alert_id,
                p.id, p.name, p.category, p.image_url,
                a.created_at
            FROM alert_subscriptions a
            JOIN products p ON p.id = a.product_id
            WHERE a.user_id = %s AND a.is_active = TRUE
            ORDER BY a.created_at DESC
            """,
            (user["id"],),
        )
        alerts = cur.fetchall()

        product_ids = [a["id"] for a in alerts]
        offers_map  = fetch_offers(cur, product_ids, stores)

        results = []
        for alert in alerts:
            offers = offers_map.get(alert["id"], [])
            results.append({
                "alert_id":   alert["alert_id"],
                "id":         alert["id"],
                "name":       alert["name"],
                "category":   alert["category"],
                "image_url":  alert["image_url"],
                "best_price_eur":    min((o["price_eur"] for o in offers if o["price_eur"]), default=None),
                "best_discount_pct": max((o["discount_pct"] for o in offers if o["discount_pct"]), default=None),
                "offers":     offers,
                "created_at": alert["created_at"].isoformat() if alert["created_at"] else None,
            })

        return {"alerts": results}
    finally:
        conn.close()


@app.get("/health")
def health():
    try:
        conn = get_db()
        conn.close()
        return {"status": "ok", "time": datetime.now().isoformat()}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))

@app.get("/ping")
def ping():
    """Lightweight endpoint for keep-alive pings. No DB call."""
    return {"pong": True}
