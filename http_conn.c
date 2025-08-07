
#include "http_conn.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

typedef struct MemoryStruct {
	char* memory;
	size_t size;
}MemoryStruct;

/**
* 代码来自官网 https://everything.curl.dev/examples/getinmem.html
*/
static size_t
mem_cb(void* contents, size_t size, size_t nmemb, void* userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct* mem = (struct MemoryStruct*)userp;

	mem->memory = realloc(mem->memory, mem->size + realsize + 1);
	if (mem->memory == NULL) {
		/* out of memory */
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = '\0';

	return realsize;
}
/**
* 调用者需要free
*/
char* http_requests(char* url)
{
	CURL* curl;
	CURLcode http_res;
	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "User-Agent: Scanner/1.0");

	MemoryStruct chunk;
	chunk.memory = malloc(1);
	chunk.size = 0;


	/*初始化libcurl*/
	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();

	if (!curl)
	{
		fprintf(stderr, "curl错误");
		return NULL;
	}
	/**
	* 设置请求URL
	*/
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, mem_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
	if (headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	http_res = curl_easy_perform(curl);
	if (http_res != CURLE_OK)
	{
		fprintf(stderr, "请求错误");
		free(chunk.memory);
		chunk.memory = NULL;
	}
	curl_easy_cleanup(curl);
	curl_global_cleanup();
	curl_slist_free_all(headers);
	return chunk.memory;
}