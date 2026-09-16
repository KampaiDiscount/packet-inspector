# HTTP login-field coverage (0.1.2)

Checked 2026-09-16. These are representative defaults from widely used
frameworks/products, not a statistically measured ranking of Internet login
forms. Applications can rename every field. The detector checks actual
transmitted form/JSON/query names, not DOM IDs, labels, or autocomplete hints.

## Primary-source coverage matrix

| Family | Identity field | Sensitive field | Primary source |
|---|---|---|---|
| WordPress | `log` | `pwd` | [wp_login_form source](https://developer.wordpress.org/reference/functions/wp_login_form/) |
| Django login | `username` | `password` | [AuthenticationForm](https://github.com/django/django/blob/stable/5.2.x/django/contrib/auth/forms.py) |
| Spring Security | `username` | `password` | [Form Login](https://docs.spring.io/spring-security/reference/7.0/servlet/authentication/passwords/form.html) |
| Legacy Spring / Java form login | `j_username` | `j_password` | [Legacy form authentication](https://docs.spring.io/spring-security/site/docs/2.0.x/reference/html/form.html) |
| Keycloak | `username` | `password` | [Login template](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources/theme/base/login/login.ftl) |
| ASP.NET Core Identity | `Input.Email` | `Input.Password` | [Login template](https://github.com/dotnet/aspnetcore/blob/main/src/Identity/UI/src/Areas/Identity/Pages/V5/Account/Login.cshtml), [name-generation semantics](https://learn.microsoft.com/en-us/aspnet/core/mvc/views/working-with-forms?view=aspnetcore-10.0#the-input-tag-helper) |
| Drupal | `name` | `pass` | [UserLoginForm](https://api.drupal.org/api/drupal/core%21modules%21user%21src%21Form%21UserLoginForm.php/class/UserLoginForm/10) |
| phpMyAdmin | `pma_username` | `pma_password` | [Login template](https://github.com/phpmyadmin/phpmyadmin/blob/master/resources/templates/login/form.twig) |
| Roundcube | `_user` | `_pass` | [HTML login form generator](https://github.com/roundcube/roundcubemail/blob/master/program/include/rcmail_output_html.php) |
| Symfony form_login | `_username` | `_password` | [Documented form convention](https://symfony.com/doc/4.x/security/form_login.html) |
| AltoroJ / Testfire lab | `uid` | `passw` | [Live public form](http://demo.testfire.net/login.jsp) |
| Vulnweb ASP lab | `tfUName` | `tfUPass` | [Live public form](http://testasp.vulnweb.com/Login.asp) |

Django also defines password-change/reset/registration fields `old_password`,
`new_password1`, `new_password2`, `password1`, and `password2` in the source above.
These are sensitive values, not necessarily login attempts. Keycloak's
[OTP form](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources/theme/base/login/login-otp.ftl)
submits `otp`; its `autocomplete="one-time-code"` is a browser hint, not that
request parameter's name.

## Matching rules

- Password bases: `password`, `passwd`, `passw`, `pwd`, `pass`, `passphrase`.
- Bounded variants cover current/old/new/confirm/repeat/retype, user/login/account,
  numbered fields, and common `txt`/`tb`/`tf`/`input`/`inp` control prefixes.
- Identity families cover user/username/user ID/UID, login name/ID, email,
  account/member identifiers, and the source-backed special cases above.
- `name`, `login`, `account`, `identifier`, and `identity` are weak identity hints.
  They are used only when no stronger identity field is present. A submit button
  named `login` therefore does not mask a real `username` field.
- More than one equally preferred identity remains explicitly unpaired.
  Identity fields never create a standalone sensitive-field event.
- OTP/TOTP and explicit one-time/MFA/two-factor/verification-code names are
  sensitive authentication-material candidates. Plain `code` is not.
- Case, separators, camelCase, dotted/bracketed namespaces, and ASP.NET `$`
  naming containers are handled without changing the original exported name.
- camelCase API/session fields such as `accessToken` and `clientSecret` are
  recognized alongside the earlier underscore variants.
- Matching uses whole normalized names or terminal components, not arbitrary
  substrings. `compass`, `passenger`, `password_policy`, `passwordLength`,
  `password[metadata]`, and `token_count` are not password/token values.
- Exact names in `extra_sensitive_field_names` remain authoritative.

All tables are precomputed once. Each bounded parsed field is classified once
per message; there is no per-packet web lookup, model call, or unbounded alias
cache. Distinct retries remain distinct evidence events. Exported original
names, values, endpoints, and provenance are retained.

## Boundaries

This is name-based candidate detection, not proof of an account relationship,
authentication success, or credential validity. An arbitrary key such as `a7`
cannot be inferred to mean password from its name alone. No response-page
learning or encrypted-traffic bypass was added. TLS/HTTPS/QUIC, HTTP/2,
multipart and compressed request-body limitations remain as documented in README.
