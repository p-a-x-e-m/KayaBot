import os
import re
import time
import json
import shutil
import logging
import sqlite3
import tempfile
import subprocess
from typing import Optional, List, Dict
from urllib.parse import urlparse
from statistics import mean
from datetime import datetime, timedelta
from collections import defaultdict

from cryptography.fernet import Fernet, InvalidToken
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

# Configuration
BASE_URL = "https://kaya.ir"
TARGET_URL = "https://kaya.ir/projects/jobs/17"
EXCLUDED_COUNTRIES = ['India', 'Pakistan', 'Bangladesh']

DB_PATH = "kaya.db"
LOG_PATH = "kaya_monitor.log"

# Log level is overridable so normal runs don't accumulate noisy detail logs.
LOG_LEVEL = os.environ.get("KAYA_LOG_LEVEL", "INFO").upper()

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def env_flag(name: str, default: bool = False) -> bool:
    """Read an environment variable as a boolean flag"""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ('1', 'true', 'yes', 'on')


def restrict_file_permissions(path: str) -> None:
    """Best-effort chmod so credential-bearing files aren't world-readable (no-op on Windows)"""
    try:
        if os.name != 'nt' and os.path.exists(path):
            os.chmod(path, 0o600)
    except OSError as e:
        logger.warning(f"Could not restrict permissions on {path}: {str(e)}")


def cleanup_previous_sessions():
    """Kill any remaining Chrome/chromedriver processes and clean temp directories

    Subprocesses are spawned without a shell and matched on an absolute pattern,
    so the cleanup cannot be turned into command execution if the process table
    contains attacker-controlled names.
    """
    # pkill is POSIX-only; on Windows leftover Chrome instances are left to the
    # OS and the temp-profile sweep below.
    pkill = shutil.which('pkill')
    if pkill:
        for process_name in ('chrome', 'chromedriver'):
            try:
                # No shell, absolute path: the pattern is a literal argument, so
                # the call cannot be turned into command execution.
                subprocess.run(
                    [pkill, '-f', process_name],
                    shell=False,
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except (OSError, subprocess.SubprocessError) as e:
                logger.warning(f"Could not kill {process_name} processes: {str(e)}")

    try:
        temp_dir = tempfile.gettempdir()
        for item in os.listdir(temp_dir):
            if item.startswith("chrome_"):
                try:
                    shutil.rmtree(os.path.join(temp_dir, item), ignore_errors=True)
                except Exception as e:
                    logger.warning(f"Error cleaning {item}: {str(e)}")

        logger.info("Previous sessions cleaned up successfully")
    except Exception as e:
        logger.warning(f"Cleanup error: {str(e)}")

class KayaAuth:
    """Handles authentication with kaya.ir using cookies"""
    
    def __init__(self, debug: bool = False):
        self.driver: Optional[webdriver.Chrome] = None
        self.debug = debug
        self.base_url = BASE_URL
        self.user_data_dir: Optional[str] = None
        self.init_db()

    def init_db(self) -> None:
        """Initialize database for cookie storage"""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                c = conn.cursor()
                c.execute('''CREATE TABLE IF NOT EXISTS cookies
                             (id INTEGER PRIMARY KEY,
                              cookies TEXT,
                              expires_at TEXT)''')
            # The rows hold live session cookies — keep them owner-readable only.
            restrict_file_permissions(DB_PATH)
            logger.debug("Database initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize database: {str(e)}")
            raise

    @staticmethod
    def _cipher() -> "Fernet":
        """Build the cipher used to protect cookies at rest"""
        raw_key = os.environ.get("KAYA_COOKIE_KEY")
        if not raw_key:
            raise ValueError(
                "KAYA_COOKIE_KEY must be set to a Fernet key "
                "(generate one with: python -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\")"
            )
        try:
            return Fernet(raw_key.encode())
        except Exception as e:
            raise ValueError(f"KAYA_COOKIE_KEY is not a valid Fernet key: {str(e)}")

    def save_cookies(self) -> None:
        """Save cookies to database, encrypted at rest"""
        if not self.driver:
            raise ValueError("Driver not initialized")

        try:
            cookies = self.driver.get_cookies()
            expires_at = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")

            # Encrypt before it ever reaches the filesystem.
            encrypted = self._cipher().encrypt(json.dumps(cookies).encode()).decode()

            with sqlite3.connect(DB_PATH) as conn:
                c = conn.cursor()
                c.execute("DELETE FROM cookies")
                c.execute("INSERT INTO cookies VALUES (1, ?, ?)", (encrypted, expires_at))
            restrict_file_permissions(DB_PATH)
            logger.info("Cookies saved to database successfully")
        except Exception as e:
            logger.error(f"Failed to save cookies: {str(e)}")
            raise

    def get_cookies(self) -> Optional[list]:
        """Retrieve and decrypt cookies from database"""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                c = conn.cursor()
                c.execute("SELECT cookies, expires_at FROM cookies WHERE id=1")
                row = c.fetchone()

            if not row:
                logger.debug("No cookies found in database")
                return None

            if datetime.now() > datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S"):
                logger.debug("Cookies expired")
                return None

            # A decryption failure means the key changed or the row is corrupt;
            # fall back to a fresh login rather than crashing.
            try:
                decrypted = self._cipher().decrypt(row[0].encode()).decode()
            except InvalidToken:
                logger.warning("Stored cookies could not be decrypted; a new login is required")
                return None

            logger.debug("Cookies retrieved from database")
            return json.loads(decrypted)
        except Exception as e:
            logger.error(f"Failed to retrieve cookies: {str(e)}")
            return None

    def init_driver(self) -> webdriver.Chrome:
        """Initialize the WebDriver

        Note: this driver deliberately keeps Chrome's default security posture.
        Do not re-add --disable-web-security, --allow-running-insecure-content,
        or the navigator.webdriver override: they weaken the browser's own
        protections (same-origin policy, TLS enforcement) for the whole session,
        including the authenticated kaya.ir session.
        """
        if self.driver is not None:
            return self.driver

        options = Options()

        # Sandbox escape is opt-in and only needed when running as root in a container.
        if env_flag("KAYA_NO_SANDBOX"):
            options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-notifications")
        options.add_argument("--disable-popup-blocking")

        # Create a private user profile with restrictive permissions
        self.user_data_dir = tempfile.mkdtemp(prefix="kaya_profile_")
        restrict_file_permissions(self.user_data_dir)
        options.add_argument(f"--user-data-dir={self.user_data_dir}")

        if not self.debug:
            options.add_argument("--headless=new")
            options.add_argument("--disable-gpu")

        try:
            service = Service(
                ChromeDriverManager().install(),
                # Not verbose: driver logs can capture page content and form values.
                service_args=[],
                log_path=os.path.abspath('chromedriver.log')
            )

            self.driver = webdriver.Chrome(service=service, options=options)

            logger.info("WebDriver initialized")
            return self.driver

        except Exception as e:
            logger.error(f"WebDriver initialization failed: {str(e)}")
            self._remove_user_data_dir()
            raise

    def _remove_user_data_dir(self) -> None:
        """Delete the throwaway browser profile"""
        if self.user_data_dir and os.path.exists(self.user_data_dir):
            shutil.rmtree(self.user_data_dir, ignore_errors=True)
            logger.info(f"Cleaned up user data directory: {self.user_data_dir}")
        self.user_data_dir = None

    def close_driver(self) -> None:
        """Close the WebDriver and clean up"""
        if self.driver is not None:
            try:
                self.driver.quit()
            except Exception as e:
                logger.error(f"Error closing driver: {str(e)}")
            finally:
                self.driver = None
                self._remove_user_data_dir()

    def _debug_artifact(self, filename: str) -> None:
        """Save a screenshot for troubleshooting — opt-in only

        Screenshots of an authenticated session can contain account details, so
        they are written only when KAYA_DEBUG_ARTIFACTS is set.
        """
        if not env_flag("KAYA_DEBUG_ARTIFACTS"):
            return
        try:
            if self.driver:
                self.driver.save_screenshot(filename)
                logger.info(f"Saved debug screenshot: {filename}")
        except Exception as e:
            logger.warning(f"Could not save screenshot {filename}: {str(e)}")

    @staticmethod
    def load_credentials() -> Dict[str, str]:
        """Load login credentials from environment variables"""
        username = os.environ.get("KAYA_USERNAME")
        password = os.environ.get("KAYA_PASSWORD")

        if not username or not password:
            raise ValueError(
                "KAYA_USERNAME and KAYA_PASSWORD environment variables must be set"
            )

        return {"loginNumber": username, "password": password}

    def manual_login(self) -> bool:
        """Perform manual login"""
        try:
            self.init_driver()
            logger.info("Opening login page")
            
            # Load login page
            self.driver.get(f"{self.base_url}/account/login")
            WebDriverWait(self.driver, 15).until(
                EC.presence_of_element_located((By.ID, "loginNumber"))
            )
            
            # Fill credentials
            credentials = self.load_credentials()

            for field_id, value in credentials.items():
                element = self.driver.find_element(By.ID, field_id)
                element.clear()
                element.send_keys(value)
                time.sleep(0.5)
            
            # Get login button
            login_button = WebDriverWait(self.driver, 30).until(
                EC.presence_of_element_located((By.XPATH, "//button[contains(., 'ورود')]"))
            )
            self._debug_artifact("login_button_state.png")

            # Click the button
            login_button.click()
            logger.info("Login button clicked")
            
            # Comprehensive login verification
            try:
                def is_logged_in(driver):
                    current_url = driver.current_url.lower()
                    conditions = [
                        "projects" in current_url,
                        "dashboard" in current_url,
                        "panel" in current_url,
                        len(driver.find_elements(By.XPATH, "//*[contains(text(), 'Welcome')]")) > 0,
                        len(driver.find_elements(By.ID, "loginNumber")) == 0,
                        len(driver.find_elements(By.XPATH, "//div[contains(@class, 'user-avatar')]")) > 0
                    ]
                    return any(conditions)
                
                WebDriverWait(self.driver, 30).until(is_logged_in)
                # Log the path only — the full URL can carry session tokens.
                logger.info(f"Login successful - path: {urlparse(self.driver.current_url).path}")

                # Additional verification steps
                time.sleep(3)

                # Check for auth cookies
                cookies = self.driver.get_cookies()
                auth_cookies = [c for c in cookies if c['name'] in ['token', 'session']]

                if not auth_cookies:
                    logger.error("No authentication cookies found")
                    self._debug_artifact("no_auth_cookies.png")
                    raise ValueError("No auth cookies found after login")

                logger.info(f"Found {len(auth_cookies)} authentication cookies")
                self.save_cookies()
                return True

            except Exception as e:
                # Never log page_source: it contains the authenticated DOM.
                logger.error(f"Login verification failed at path: {urlparse(self.driver.current_url).path}")
                self._debug_artifact("login_verification_failed.png")
                raise ValueError(f"Login verification failed: {str(e)}")

        except Exception as e:
            logger.error(f"Login process failed: {str(e)}", exc_info=True)
            self._debug_artifact("login_process_failed.png")
            raise

    def set_cookies(self) -> bool:
        """Set cookies with enhanced verification"""
        try:
            # Get cookies from database
            cookies = self.get_cookies()
            if not cookies:
                logger.warning("No valid cookies found in database")
                return False

            # Initialize new driver session
            self.init_driver()
            
            # First visit the domain to set cookies
            self.driver.get(f"{self.base_url}/")
            time.sleep(2)
            
            # Clear existing cookies
            self.driver.delete_all_cookies()
            logger.info("Cleared existing cookies")
            
            # Prepare domain for comparison
            domain = self.base_url.split('//')[1].split(':')[0]
            
            # Set each cookie with proper validation
            success_count = 0
            for cookie in cookies:
                try:
                    # Skip invalid cookies
                    if not all(k in cookie for k in ['name', 'value', 'domain']):
                        continue
                        
                    # Fix domain format
                    cookie_domain = cookie['domain'].lstrip('.')
                    if domain not in cookie_domain:
                        logger.debug(f"Skipping cookie for different domain: {cookie['name']}")
                        continue
                    
                    # Prepare cookie dict
                    cookie_to_set = {
                        'name': cookie['name'],
                        'value': cookie['value'],
                        'domain': cookie_domain,
                        'path': cookie.get('path', '/')
                    }
                    
                    # Add optional attributes if they exist
                    for attr in ['expiry', 'secure', 'httpOnly']:
                        if attr in cookie:
                            cookie_to_set[attr] = cookie[attr]
                    
                    # Set the cookie
                    self.driver.add_cookie(cookie_to_set)
                    success_count += 1
                    logger.debug(f"Successfully set cookie: {cookie['name']}")
                    
                except Exception as e:
                    logger.warning(f"Failed to set cookie {cookie.get('name')}: {str(e)}")
                    continue
            
            if success_count == 0:
                logger.error("No cookies were successfully set")
                return False
                
            logger.info(f"Successfully set {success_count}/{len(cookies)} cookies")
            
            # Refresh and verify login
            self.driver.refresh()
            time.sleep(3)
            
            # Enhanced verification
            verification_passed = False
            try:
                # Check 1: URL contains auth indicators
                current_url = self.driver.current_url.lower()
                if any(x in current_url for x in ['dashboard', 'panel', 'account']):
                    verification_passed = True
                
                # Check 2: Presence of user elements
                if not verification_passed:
                    user_elements = self.driver.find_elements(By.XPATH, "//*[contains(@class, 'user') or contains(text(), 'Welcome')]")
                    if user_elements:
                        verification_passed = True
                
                # Check 3: Auth cookies present
                if not verification_passed:
                    current_cookies = self.driver.get_cookies()
                    if any(c['name'] == 'token' for c in current_cookies):
                        verification_passed = True
                
                if verification_passed:
                    logger.info("Cookie authentication verified successfully")
                    return True
                else:
                    raise ValueError("Could not verify authentication after setting cookies")
                    
            except Exception as e:
                logger.error(f"Cookie verification failed at path: {urlparse(self.driver.current_url).path}")
                self._debug_artifact("cookie_verification_failed.png")

                # Diagnostic logging — cookie names only, never values.
                current_cookies = self.driver.get_cookies()
                logger.debug(f"Current cookie names: {[c['name'] for c in current_cookies]}")

                return False
                
        except Exception as e:
            logger.error(f"Failed to set cookies: {str(e)}", exc_info=True)
            return False

    def auth(self) -> bool:
        """Main authentication method"""
        try:
            if self.get_cookies():
                logger.info("Cookies loaded from database")
                if self.set_cookies():
                    logger.info("Authentication successful using stored cookies")
                    return True

            logger.info("Manual login required")
            if self.manual_login():
                logger.info("Authentication completed successfully")
                return True
            return False
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False

    def reconnect(self) -> bool:
        """Reconnect the browser session"""
        try:
            self.close_driver()
            if not self.auth():
                return False
            logger.info("Reconnected successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to reconnect: {str(e)}")
            return False

class KayaProjectMonitor:
    def __init__(self, auth: KayaAuth):
        self.auth = auth
        self.base_url = BASE_URL
        self.target_url = TARGET_URL
        # List of countries to exclude from scraping
        self.excluded_countries = EXCLUDED_COUNTRIES

    def parse_project_time(self, time_str):
        """Parse project time string (e.g. '1:19') into datetime object"""
        try:
            now = datetime.now()
            hours, minutes = map(int, time_str.split(':'))
            project_time = now.replace(hour=hours, minute=minutes, second=0, microsecond=0)
            if project_time > now:
                project_time -= timedelta(days=1)
            return project_time
        except Exception as e:
            logger.warning(f"Failed to parse time '{time_str}': {str(e)}")
            return None

    def parse_price(self, price_str):
        """Convert price string like '250 - 30' to average value (140)"""
        try:
            cleaned = re.sub(r'[^\d\s-]', '', price_str)
            numbers = [int(num) for num in re.findall(r'\d+', cleaned)]
            return mean(numbers) if numbers else None
        except Exception as e:
            logger.warning(f"Failed to parse price '{price_str}': {str(e)}")
            return None

    def get_recent_projects(self, minutes_ago):
        """Get projects posted in the last X minutes with their prices and URLs"""
        try:
            if not hasattr(self.auth, 'driver') or not self.auth.driver:
                if not self.auth.auth():
                    logger.error("Authentication failed")
                    return []

            if self.auth.driver.current_url == self.target_url:
                self.auth.driver.refresh()
            else:
                self.auth.driver.get(self.target_url)

            WebDriverWait(self.auth.driver, 20).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, ".group.font-DMSans")))
            
            cutoff_time = datetime.now() - timedelta(minutes=minutes_ago)
            projects = self.auth.driver.find_elements(By.CSS_SELECTOR, ".group.font-DMSans")
            recent_projects = []
            
            for project in projects:
                try:
                    # Extract country information
                    country_element = project.find_element(By.CSS_SELECTOR, "span.font-medium.text-\\[\\#7A7A7A\\]")
                    country_text = country_element.text.strip()
                    
                    # Check if country is in excluded list
                    if any(excluded in country_text for excluded in self.excluded_countries):
                        logger.debug(f"Skipping project from excluded country: {country_text}")
                        continue
                    
                    # Extract project details with more precise selectors
                    title = project.find_element(By.CSS_SELECTOR, "a[href^='/projects/'] > div").text.strip()
                    url = project.find_element(By.CSS_SELECTOR, "a[href^='/projects/']").get_attribute("href")
                    full_url = f"{self.base_url}{url}" if url.startswith("/") else url
                    
                    # Correct time element selector - look for time format (HH:MM)
                    time_element = project.find_element(By.XPATH, ".//span[contains(@class, 'text-[13px]') and contains(text(), ':')]")
                    time_str = time_element.text.strip()
                    
                    price_element = project.find_element(By.CSS_SELECTOR, "div.flex.flex-row.justify-end span:nth-child(2)")
                    price_str = price_element.text.strip()
                    
                    project_time = self.parse_project_time(time_str)
                    price_avg = self.parse_price(price_str)
                    
                    if project_time and project_time >= cutoff_time and price_avg:
                        project_info = {
                            'title': title,
                            'price': price_str,
                            'price_avg': price_avg,
                            'time': project_time.strftime("%H:%M"),
                            'url': full_url,
                            'country': country_text
                        }
                        recent_projects.append(project_info)
                        
                except Exception as e:
                    logger.warning(f"Error processing project element: {str(e)}")
                    continue
            
            return recent_projects

        except Exception as e:
            logger.error(f"Error getting projects: {str(e)}", exc_info=True)
            return []

    def open_project_urls(self, projects):
        """Open project URLs one by one, fill fields and submit proposals"""
        try:
            if not projects:
                logger.info("No projects to open")
                return

            # Load description from file
            try:
                with open('descriptions.txt', 'r', encoding='utf-8') as f:
                    description_text = f.read().strip()
                logger.info("Description text loaded from file")
            except Exception as e:
                logger.error(f"Failed to load description file: {str(e)}")
                description_text = "Default description text"

            logger.info(f"Opening {len(projects)} project URLs...")
            
            for i, project in enumerate(projects, 1):
                try:
                    logger.info(f"Processing project {i}/{len(projects)}: {project['title']}")
                    self.auth.driver.get(project['url'])
                    
                    # Wait for page to load
                    WebDriverWait(self.auth.driver, 15).until(
                        EC.presence_of_element_located((By.TAG_NAME, "body")))
                    
                    # Fill price field
                    try:
                        price_input = WebDriverWait(self.auth.driver, 5).until(
                            EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='amount']")))
                        price_input.clear()
                        price_input.send_keys(str(int(project['price_avg'])))
                    except Exception as e:
                        logger.warning(f"Could not fill price field: {str(e)}")
                        continue
                    
                    # Fill days field
                    try:
                        days_input = WebDriverWait(self.auth.driver, 5).until(
                            EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='period']")))
                        days_input.clear()
                        days_input.send_keys("7")
                    except Exception as e:
                        logger.warning(f"Could not fill days field: {str(e)}")
                        continue
                    
                    # Fill description field
                    try:
                        description_input = WebDriverWait(self.auth.driver, 5).until(
                            EC.presence_of_element_located((By.CSS_SELECTOR, "textarea[name='description']")))
                        description_input.clear()
                        description_input.send_keys(description_text)
                        logger.info("Filled description field")
                    except Exception as e:
                        logger.warning(f"Could not fill description field: {str(e)}")
                        continue
                    
                    # Click submit button
                    try:
                        submit_button = WebDriverWait(self.auth.driver, 10).until(
                            EC.element_to_be_clickable((By.CSS_SELECTOR, "button.bg-\\[\\#5BBB7B\\]")))
                        submit_button.click()
                        logger.info("Clicked submit button")
                        
                        # Wait for submission to complete
                        time.sleep(5)
                        
                        # Verify submission success
                        try:
                            success_element = WebDriverWait(self.auth.driver, 10).until(
                                EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'success')]")))
                            logger.info("Proposal submitted successfully")
                        except:
                            logger.warning("Submission success verification failed")
                        
                    except Exception as e:
                        logger.error(f"Failed to click submit button: {str(e)}")
                        continue
                                        
                    # Add delay before next project
                    time.sleep(3)
                    
                except Exception as e:
                    logger.error(f"Failed to process project URL {project['url']}: {str(e)}")
                    continue

            logger.info("Finished processing all projects")
            
        except Exception as e:
            logger.error(f"Error in open_project_urls: {str(e)}")
            raise

    def monitor_new_projects(self, check_interval=7):
        """Monitor for new projects every X minutes and open their URLs"""
        seen_projects = defaultdict(bool)
        first_run = True
        
        try:
            # Initialize the session once
            if not self.auth.auth():
                logger.error("Initial authentication failed")
                return

            while True:
                logger.info(f"\n{'='*40}")
                logger.info(f"Checking for new projects at {datetime.now().strftime('%H:%M:%S')}")
                
                recent_projects = self.get_recent_projects(minutes_ago=check_interval*2)
                
                if not recent_projects:
                    logger.info("No new projects found")
                else:
                    new_projects = [
                        p for p in recent_projects 
                        if not seen_projects[p['url']]]
                    
                    for p in new_projects:
                        seen_projects[p['url']] = True
                    
                    if new_projects:
                        logger.info(f"Found {len(new_projects)} NEW projects!")
                        for i, p in enumerate(new_projects, 1):
                            logger.info(f"{i}. {p['title']} | Price: {p['price']} (Avg: {p['price_avg']}) | Country: {p.get('country', 'N/A')} | Posted at: {p['time']}")
                        
                        # Open the URLs of new projects
                        self.open_project_urls(new_projects)
                    elif not first_run:
                        logger.info("No NEW projects since last check")
                
                logger.info(f"Next check in {check_interval} minutes...")
                logger.info("="*40)
                
                first_run = False
                time.sleep(check_interval * 60)
                
        except KeyboardInterrupt:
            logger.info("\nMonitoring stopped by user")
            self.auth.close_driver()
        except Exception as e:
            logger.error(f"Monitoring error: {str(e)}")
            self.auth.close_driver()

if __name__ == "__main__":
    cleanup_previous_sessions()

    # Debug (visible browser) is opt-in via KAYA_DEBUG rather than on by default.
    debug_mode = env_flag("KAYA_DEBUG")
    interval = int(os.environ.get("KAYA_CHECK_INTERVAL", "5"))

    auth = KayaAuth(debug=debug_mode)
    monitor = KayaProjectMonitor(auth)
    
    print("Starting Kaya.ir Project Monitor")
    print("Monitoring URL:", monitor.target_url)
    print("Excluded countries:", monitor.excluded_countries)
    print("Press Ctrl+C to stop\n")
    
    monitor.monitor_new_projects(check_interval=interval)