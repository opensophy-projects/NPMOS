// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// @file ngx_cp_http_usercheck.h
/// \brief This file contains the string for the block-page returned instead of the normal server response

// NginxionS: a small neutral page instead of the page of Check Point (278 KB: its logos in base64, its name in the
// footer). The agent fills in the title and the text of the custom response of the policy (GUI: WAF -> Policy ->
// custom responses) and the incident ID; a 403 is replaced by the block page of NginxionS (Agents -> Block page).
// The three placeholders stay in this order: title, body, incident ID (initialize_web_response_data).
"<!DOCTYPE html>\n"
"<html><head><meta charset=\"UTF-8\"><meta name=\"robots\" content=\"noindex,nofollow\">\n"
"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Request blocked</title>\n"
"<style>:root{color-scheme:light dark}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;"
"box-sizing:border-box;font-family:-apple-system,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif;"
"background:#f6f6f7;color:#18181b}main{max-width:34rem;width:100%;padding:2rem;border-radius:16px;background:#fff;"
"box-shadow:0 1px 2px rgba(0,0,0,.06),0 8px 24px rgba(0,0,0,.06);border-top:4px solid #e5484d}"
"h1{margin:0 0 1rem;font-size:1.5rem;font-weight:600}p{margin:0 0 .75rem;line-height:1.55;color:#3f3f46}"
".id{margin-top:1.25rem;padding-top:1rem;border-top:1px solid #e4e4e7;font-size:.8125rem;color:#71717a;"
"font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}"
"@media (prefers-color-scheme:dark){body{background:#0f0f11;color:#f4f4f5}main{background:#18181b;box-shadow:none}"
"p{color:#d4d4d8}.id{border-color:#27272a;color:#a1a1aa}}</style></head>\n"
"<body><main><h1><!-- CHECK_POINT_USERCHECK_TITLE_PLACEHOLDER--></h1>\n"
"<p><!-- CHECK_POINT_USERCHECK_BODY_PLACEHOLDER--></p>\n"
"<div class=\"id\"><!-- CHECK_POINT_USERCHECK_UUID_PLACEHOLDER--></div></main></body></html>\n";
