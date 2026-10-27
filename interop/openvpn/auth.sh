#!/bin/sh
# auth-user-pass-verify (via-env) of the interop servers: user "alice",
# password "alice-password", one-time code "123456". $1 says how the code
# arrives:
#   password  no code, the password alone;
#   static    static-challenge: SCRV1:base64(password):base64(code);
#   dynamic   the password first, answered with a CRV1 challenge (written
#             to auth_failed_reason_file, sent with AUTH_FAILED), then
#             CRV1::<state>::<code> on the next connection.
user=alice pass=alice-password otp=123456 state=omnitun-state
[ "$username" = "$user" ] || exit 1
case $1 in
password)
    [ "$password" = "$pass" ]
    ;;
static)
    case $password in SCRV1:*:*) ;; *) exit 1 ;; esac
    rest=${password#SCRV1:}
    [ "$(printf %s "${rest%%:*}" | base64 -d)" = "$pass" ] && [ "$(printf %s "${rest#*:}" | base64 -d)" = "$otp" ]
    ;;
dynamic)
    case $password in
    "CRV1::$state::$otp") exit 0 ;;
    "$pass")
        printf 'CRV1:R,E:%s:%s:Enter the code' "$state" "$(printf %s "$user" | base64)" >"$auth_failed_reason_file"
        exit 1
        ;;
    *) exit 1 ;;
    esac
    ;;
*) exit 1 ;;
esac
