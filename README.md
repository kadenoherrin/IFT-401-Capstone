# IFT 401 Capstone: Stock Trading Platform

Welcome to our IFT-401 Capstone Project — a full-stack stock trading simulation platform built on Flask and MySQL. Users can buy/sell stocks, manage portfolios, and experience real-time price fluctuations just like in the real world.

---

## 👥 Team Members:

- **Kaden O'Herrin** 
- **Aden Ashton** 
- **Chad Mello**


---

## 🧠 Key Features

- 🔐 **User Authentication** – Register, login, and manage your profile
- 💵 **Real-Time Trading** – Buy/sell stocks with fluctuating prices
- 📊 **Live Market Simulation** – Prices change automatically every few seconds
- 📆 **Trading Hours & Holidays** – Market opens/closes based on admin settings and US holidays
- 🛠️ **Admin Panel** – Manage users, stocks, market times, and price fluctuation
- 📦 **Containerized** – Run the entire stack with Docker and Docker Compose

---

## 🐳 Running the App with Docker

### ⚙️ Prerequisites

Before you begin, make sure you have the following installed:

- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)

---

### 📦 Installation

 - Two apps are required for this application - the Web App, and MySQL

 - To compile locally:

Run MySQL server on your local host, and run the following commands:
```
 git clone https://github.com/yourusername/ift-401-capstone.git

 cd ift-401-capstone

 nano .env
```
Add the following text, replacing the variables with the values matching your MySQL Database:
```
SQL_PASSWORD=password
SQL_USERNAME=root
SQL_DATABASE=database
SQL_HOST=db
```
---
- To run via Docker:

Set system environment variables or use a local .env file:

 ```
docker run -d \
  --name capstone-db \
  -e MYSQL_ROOT_PASSWORD=${SQL_PASSWORD} \
  -e MYSQL_DATABASE=${SQL_DATABASE} \
  -p 3306:3306 \
  -v capstone_db_data:/var/lib/mysql \
  --health-cmd="mysqladmin ping -h localhost" \
  --health-interval=5s \
  --health-timeout=5s \
  --health-retries=10 \
  mysql:latest
 ```
```
docker run -d \
  --name capstone-web \
  --link capstone-db:db \
  -e SQL_HOST=${SQL_HOST} \
  -e SQL_USERNAME=${SQL_USERNAME} \
  -e SQL_PASSWORD=${SQL_PASSWORD} \
  -e SQL_DATABASE=${SQL_DATABASE} \
  -p 5000:5000 \
  ghcr.io/omegawaffle/ift-401-capstone:latest
```

- Docker compose:
```
services:
  web:
    container_name: capstone-web
    image: ghcr.io/omegawaffle/ift-401-capstone:latest
    ports:
      - "5000:5000"
    environment:
      - SQL_HOST=${SQL_HOST}
      - SQL_USERNAME=${SQL_USERNAME}
      - SQL_PASSWORD=${SQL_PASSWORD}
      - SQL_DATABASE=${SQL_DATABASE}
    depends_on:
      db:
        condition: service_healthy

  db:
    image: mysql:latest
    restart: always
    container_name: capstone-db
    ports:
      - "3306:3306"
    environment:
      - MYSQL_ROOT_PASSWORD=${SQL_PASSWORD}
      - MYSQL_DATABASE=${SQL_DATABASE}
    volumes:
      - db_data:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 5s
      timeout: 5s
      retries: 10

volumes:
  db_data:
```
---
- Kubernetes:
```
Use the provided manifests to deploy the app on your cluster. Any persistent storage can be used, but the PV and PVC is setup to use a local NFS server. Change password in the Secret to your liking.
```
```
kubectl apply -f pv.yaml
kubectl apply -f pvc.yaml
kubectl apply -f secret.yaml
kubectl apply -f mysql.yaml
kubectl apply -f flaskapp.yaml
```




---
📄 License

MIT License © 2025 — IFT-401 Team
