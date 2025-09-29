# 🛡️ CSRF Exploit Lab – Email Change Vulnerability

This lab demonstrates how an attacker can exploit **Cross-Site Request Forgery (CSRF)** using different vulnerability to change the email address of a logged-in user.

---

## 🎯 Objective

Exploit a vulnerability where:

- Login as **admin@admin.com** to get the flag
- A **CSRF token** is generated per account and refreshed on every `/account` page load.
- The application validates CSRF tokens on all update requests.

Your goal is to **perform a email change without the user’s consent** while they're logged in. A Bot logs in as admin to view all your posts. 

---

## 🚀 Run the Lab via Docker

Start the lab locally using:

```bash
docker pull xploiterd/secureme
docker run -p 8000:8000 xploiterd/secureme
