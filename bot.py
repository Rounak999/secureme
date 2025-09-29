#!/usr/bin/env python3
"""
bot.py -- headless Selenium bot for CTF admin simulation.

Behavior:
 - Launch headless Chromium/Chrome (accepts self-signed certs)
 - Visit https://127.0.0.1:8000
 - Login with credentials (ADMIN_EMAIL, ADMIN_PASS)
 - Wait 10 seconds (so blind XSS payloads have time to execute)
 - Quit

Notes:
 - Ensure chromedriver is installed and on PATH (or set CHROMEDRIVER_PATH env var).
 - If Chromium binary is at a nonstandard location, set CHROME_BIN env var.
"""

import os
import time
import logging
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException,
    NoSuchElementException,
    WebDriverException,
)

# Configuration (change if needed or set via environment variables)
URL = os.environ.get("TARGET_URL", "https://127.0.0.1:8000")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@admin.com")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "**********")
LOGIN_TIMEOUT = int(os.environ.get("LOGIN_TIMEOUT", "10"))   # seconds to wait for login elements
POST_LOGIN_WAIT = int(os.environ.get("POST_LOGIN_WAIT", "10"))  # seconds to wait after login
CHROME_BIN = os.environ.get("CHROME_BIN", "/usr/bin/chromium")  # container default
CHROMEDRIVER_PATH = os.environ.get("CHROMEDRIVER_PATH", None)   # optional path to chromedriver

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("ctf-bot")


def make_driver():
    """Create a headless Chrome/Chromium webdriver that accepts insecure certs."""
    options = webdriver.ChromeOptions()

    # Headless mode suitable for recent Chrome. If older items, change accordingly.
    options.add_argument("--headless=new")        # use new headless; if unsupported, change to "--headless"
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-extensions")
    options.add_argument("--window-size=1280,800")

    # Avoid detection in some cases (optional)
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)

    # Accept self-signed certs
    options.set_capability("acceptInsecureCerts", True)
    # Explicit flag as fallback
    options.add_argument("--ignore-certificate-errors")

    # If CHROME_BIN exists, point Chrome there (helpful in Docker)
    if CHROME_BIN and os.path.exists(CHROME_BIN):
        options.binary_location = CHROME_BIN
        logger.debug("Using chrome binary at %s", CHROME_BIN)
    else:
        logger.debug("CHROME_BIN not set or not found; relying on system default browser binary")

    # Create Service object if a specific chromedriver path is provided
    service = Service(CHROMEDRIVER_PATH) if CHROMEDRIVER_PATH else Service()

    try:
        driver = webdriver.Chrome(service=service, options=options)
        # Optional: small implicit wait
        driver.implicitly_wait(1)
        logger.info("Launched headless browser")
        return driver
    except WebDriverException as e:
        logger.exception("Failed to start WebDriver: %s", e)
        raise


def do_login(driver):
    """Perform the login flow and wait post-login for POST_LOGIN_WAIT seconds."""
    logger.info("Opening %s", URL)
    try:
        driver.get(URL)
    except WebDriverException as e:
        logger.exception("Error opening URL: %s", e)
        return False

    wait = WebDriverWait(driver, LOGIN_TIMEOUT)

    try:
        # Wait for email and password inputs to be present
        email_el = wait.until(EC.presence_of_element_located((By.NAME, "email")))
        pwd_el = wait.until(EC.presence_of_element_located((By.NAME, "password")))
        logger.info("Found login form elements")
    except TimeoutException:
        logger.error("Login inputs not found within %s seconds", LOGIN_TIMEOUT)
        return False

    # Fill credentials
    try:
        email_el.clear()
        email_el.send_keys(ADMIN_EMAIL)
        pwd_el.clear()
        pwd_el.send_keys(ADMIN_PASS)
        logger.info("Filled credentials for %s", ADMIN_EMAIL)
    except Exception as e:
        logger.exception("Failed to enter credentials: %s", e)
        return False

    # Submit form:
    try:
        # prefer clicking submit button if present
        try:
            submit_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            submit_btn.click()
            logger.info("Clicked submit button")
        except NoSuchElementException:
            # fallback: submit the form via Enter on password field
            pwd_el.send_keys("\n")
            logger.info("Submitted form via ENTER key")
    except Exception as e:
        logger.exception("Error submitting form: %s", e)
        return False

    # Optional: wait for a URL change or a redirect as a sign of success
    try:
        WebDriverWait(driver, 5).until(lambda d: d.current_url != URL)
        logger.info("URL changed after login: %s", driver.current_url)
    except TimeoutException:
        logger.warning("No URL change after login (this may be normal depending on your app)")

    # Wait to allow blind XSS payloads to fire / JS to run in admin context
    logger.info("Waiting %s seconds post-login for payload execution...", POST_LOGIN_WAIT)
    time.sleep(POST_LOGIN_WAIT)

    return True


def main():
    driver = None
    try:
        driver = make_driver()
        success = do_login(driver)
        if success:
            logger.info("Bot run completed successfully")
        else:
            logger.warning("Bot run finished with errors (see logs)")
    except Exception as e:
        logger.exception("Unexpected error in bot: %s", e)
    finally:
        if driver:
            try:
                driver.quit()
                logger.info("Browser closed")
            except Exception:
                pass


if __name__ == "__main__":
    main()
