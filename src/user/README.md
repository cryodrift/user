# User

User-related utilities and web endpoints (login, logout, 2FA, password and email management).

## Routes

All routes are provided by methods annotated with `@web` in `src/user/Web.php` and are accessible under `/user/{method}`. Available routes and parameters:

- GET or POST /user/login — login form and submission
  - params:
    - user (POST only, required, string)
    - password (POST only, required, string)
    - code (POST only, optional, string): 2FA code (if 2FA enabled)

- GET /user/logout — destroy session and redirect
  - params: none

- GET /user/admin — user administration page
  - params: none

- GET or POST /user/index — start page / 2FA verification
  - params:
    - query (POST only, optional, string): 2FA verification code

- GET or POST /user/api — grouped API endpoints by command
  - params:
    - command (required, string): one of 2fa | password | email | emaildelete
    - for command=2fa:
      - params: none (returns 2FA setup info)
    - for command=password:
      - value (POST, JSON object): { "old_password": string, "new_password": string }
    - for command=email:
      - value (POST, JSON object): { "type": string, "name": string, "host": string, "password": string }
    - for command=emaildelete:
      - data-id (POST, JSON object): { "data-id": string } — encrypted host id

## CLI

- Show commands:
  php index.php /user/cli -help
