# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.
#
# Shared proxy settings. X-Forwarded-Proto is what lets the API tell HTTPS clients apart from
# plaintext ones (TRUSTED_PROXY_IPS must include this nginx container's network for the header
# to be honoured).

proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header Connection "";
proxy_connect_timeout 5s;
proxy_send_timeout 120s;
proxy_read_timeout 120s;
proxy_request_buffering on;
