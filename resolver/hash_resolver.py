from bs4 import BeautifulSoup
from cachetools import TTLCache
from timeit import default_timer as timer

import random
import requests
import time

# The result cache
result_cache = TTLCache(maxsize=10, ttl=30)


class HashResolverConfig:
    check_delay: int = 5

    proxy: str = ''

    use_cache: bool = True
    max_cache_size: int = 2500
    cache_ttl: int = 600

    def __int__(self):
        pass

    # hashes.com handles ratelimiting differently from most sites.
    #
    # Instead of simply returning a 429 when you send an excessive
    # amount of requests, they completely blacklist your IP address
    # for around a month. In order to get around this, there is a
    # configurable minimum delay between hash searches.
    #
    # Whether the delay is active
    def use_delay(self) -> bool:
        return self.check_delay > 0

    # Returns the delay
    def get_delay(self) -> int:
        return self.check_delay

    # Returns the proxy to be used in requests
    def get_proxy(self) -> str:
        return self.proxy

    # Returns if searches should be cached
    def cache_results(self) -> bool:
        return self.use_cache

    # Returns the max results of the cache
    def get_max_cache_size(self) -> int:
        return self.max_cache_size

    # Returns the lifetime of cache entries
    def get_cache_ttl(self) -> int:
        return self.cache_ttl

    # Sets the delay to the provided parameter
    def set_delay(self, delay: int) -> None:
        self.check_delay = delay

    # Sets the proxy to the provided parameter
    def set_proxy(self, proxy: str) -> None:
        self.proxy = proxy

    # Sets if the program should use the cache
    def set_use_cache(self, use_cache: bool) -> None:
        self.use_cache = use_cache

    # Sets the maximum amount of entries in the cache
    def set_max_cache_size(self, max_cache_size: int) -> None:
        global result_cache
        result_cache = TTLCache(maxsize=max_cache_size, ttl=self.cache_ttl)

        self.max_cache_size = max_cache_size

    # Sets the cache entry lifespan
    def set_cache_ttl(self, cache_ttl: int) -> None:
        global result_cache
        result_cache = TTLCache(maxsize=self.max_cache_size, ttl=cache_ttl)

        self.cache_ttl = cache_ttl


# The dictionary to be used to generate the CSRF token
dictionary = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
    'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9'
]

# The hash resolver configuration
config = HashResolverConfig()

# The time of the most recent hash search
last_hash_search = 0


# An error to be thrown when a hash can't be decrypted
# with hashes.com
class HashNotFoundError(Exception):

    def __init__(self, requested_hash: str):
        self.requested_hash = requested_hash


# An error to be thrown when the status code from hashes.com
# indicates that the client is either rate limited or their IP
# address is blacklisted
class RateLimitOrBlacklistError(Exception):

    def __init__(self, requested_hash: str, message: str, status_code: int):
        self.requested_hash = requested_hash
        self.message = message
        self.status_code = status_code


# Uses hashes.com to decrypt a hash
def decrypt_hash(hashed_content: str) -> str:
    global result_cache

    if hashed_content in result_cache:
        cache_result = result_cache[hashed_content]

        print('Cached result found!')

        # The cached result is empty, so the hash couldn't be found
        if cache_result == '':
            raise HashNotFoundError(hashed_content)

        return cache_result

    global last_hash_search

    # Cooldown system for hash searching, to ensure the client
    # IP address doesn't get rate limited
    if config.use_delay() and last_hash_search is not 0:
        time_elapsed = last_hash_search - timer()
        last_hash_search = timer()

        if time_elapsed < config.get_delay():
            time.sleep(config.get_delay() - time_elapsed)
    else:
        last_hash_search = timer()

    session = requests.Session()

    # If the client is configured to use a proxy, then we
    # set the proxies for the session

    if config.proxy != '':
        session.proxies = {
            'http': config.proxy,
            'https': config.proxy
        }

    response = session.post('https://hashes.com/en/decrypt/hash', data={
        # The CSRF token can be left empty, but I prefer to leave it populated
        # in case hashes.com decides to require it eventually

        'csrf_token': ''.join(random.choices(dictionary, k=32)),
        'hashes': hashed_content,
        'submitted': 'true'
    })

    # If the response has an abnormal status code, the client IP was
    # most likely rate limited or blacklisted, so we throw an exception
    if response.status_code != 200:
        raise RateLimitOrBlacklistError(hashed_content, response.text, response.status_code)

    # Use BeautifulSoup to parse the HTML
    soup = BeautifulSoup(response.text, 'html.parser')

    # All divs with the py-1 class
    divs = soup.find_all('div', {'class': 'py-1'})

    # If there are no divs that have the provided class, the hash couldn't be found
    if len(divs) == 0:
        # Add an empty string to the cache
        result_cache[hashed_content] = ''

        # Throw an exception to show that the hash was not found
        raise HashNotFoundError(hashed_content)

    results = divs[0].text.split(':')
    result = results[len(results) - 1]

    # Add the result to the cache
    result_cache[hashed_content] = result

    return result
