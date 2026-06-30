#ifndef UTIL_H
#define UTIL_H

const char *random_ua(void);

#ifndef HTTP_ONLY
#include <curl/curl.h>
void curl_apply_opsec(CURL *curl);
#endif /* HTTP_ONLY */

#endif /* UTIL_H */
