/*
 * SPDX-License-Identifier: MPL-2.0
 * SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
 *
 * Drives the whole C ABI through include/seylock.h only, so the header cannot
 * drift from the library. Run by tools/check_c_abi.sh.
 */
#include <stdio.h>
#include <string.h>
#include "seylock.h"

#define CHECK(cond, what)                                   \
    do {                                                    \
        if (!(cond)) {                                      \
            fprintf(stderr, "FAIL: %s\n", what);            \
            return 1;                                       \
        }                                                   \
    } while (0)

static const char *POLICY =
    "{\"list\":{\"v\":2,\"issued_at_ms\":1,\"expires_at_ms\":9000000000000,"
    "\"services\":{\"api\":\"https://api.invalid\"},"
    "\"paths\":[{\"kind\":\"direct\"}]},"
    "\"network_id\":\"wifi:a\",\"race\":{}}";

int main(void) {
    char *version = seylock_version();
    CHECK(version != NULL && strlen(version) > 0, "version");
    printf("seylock %s\n", version);
    seylock_string_free(version);

    char *doc = NULL;
    CHECK(seylock_endpoints_verify("not json", "AAAA", 1, 0, &doc) == 1, "verify rejects with 1");
    CHECK(doc == NULL, "no document on rejection");
    CHECK(seylock_endpoints_verify(NULL, "AAAA", 1, 0, NULL) == 100, "NULL is 100");

    CHECK(seylock_status_json() == NULL, "no status before start");
    CHECK(seylock_stop() == 102, "stop before start is 102");

    uint16_t port = 0;
    char *token = NULL;
    CHECK(seylock_start("{", &port, &token) == 104, "bad policy JSON is 104");
    CHECK(seylock_start(POLICY, &port, &token) == 0, "start");
    CHECK(port > 0 && token != NULL && strlen(token) > 0, "port and token");
    CHECK(seylock_start(POLICY, &port, &token) == 101, "second start is 101");

    CHECK(seylock_set_network("cell:b") == 0, "set network");
    char *status = seylock_status_json();
    CHECK(status != NULL && strstr(status, "\"network_id\":\"cell:b\"") != NULL, "status shows the network");
    seylock_string_free(status);
    CHECK(seylock_update(POLICY) == 0, "update");

    CHECK(seylock_stop() == 0, "stop");
    seylock_string_free(token);
    seylock_string_free(NULL);
    printf("C ABI: all checks passed\n");
    return 0;
}
