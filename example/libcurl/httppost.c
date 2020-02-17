#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>

size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
       return size * nmemb;
}

static void x(void)
{
    {
        CURL *curl;
        CURLcode res;

        /* In windows, this will init the winsock stuff */ 

        /* get a curl handle */ 
        curl = curl_easy_init();
        if(curl) {
            /* First set the URL that is about to receive our POST. This URL can
               just as well be a https:// URL if that is what should receive the
               data. */ 
            curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8000/");
            //curl_easy_setopt(curl, CURLOPT_URL, "ftp://localhost:8000/a.bin");
            //curl_easy_setopt(curl, CURLOPT_URL, "rtmp://localhost/a.bin");
            /* Now specify the POST data */ 
            //curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "name=daniel&project=curl");
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);

            /* Perform the request, res will get the return code */ 
            res = curl_easy_perform(curl);
            /* Check for errors */ 
            /*
            if(res != CURLE_OK)
                fprintf(stderr, "curl_easy_perform() failed: %s\n",
                        curl_easy_strerror(res));
            */

            /* always cleanup */ 
            curl_easy_cleanup(curl);
        }
    }
}

typedef void (*CreateNetAPIOverlay_type)(const uint8_t*, const size_t);
typedef void (*DestroyNetAPIOverlay_type)(void);

CreateNetAPIOverlay_type CreateNetAPIOverlay = NULL;
DestroyNetAPIOverlay_type DestroyNetAPIOverlay = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    CreateNetAPIOverlay = (CreateNetAPIOverlay_type)dlsym(RTLD_NEXT, "CreateNetAPIOverlay");
    DestroyNetAPIOverlay = (DestroyNetAPIOverlay_type)dlsym(RTLD_NEXT, "DestroyNetAPIOverlay");
    if ( CreateNetAPIOverlay == NULL || DestroyNetAPIOverlay == NULL ) {
        abort();
    }
        curl_global_init(CURL_GLOBAL_ALL);

        //curl_global_cleanup();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    CreateNetAPIOverlay(data, size);
    x();
    DestroyNetAPIOverlay();
    return 0;
}
