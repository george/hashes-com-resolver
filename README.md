# hashes.com resolver

### Purpose

This is a Python utility program that allows you to easily use hashes.com
to reverse a hash, within your own program.

### Configuration

hashes.com has measures in place to prevent bots from scraping data.
In order to account for these measures, this program has a configuration
class, allowing you to customize the anti detection measures used.

The following are the configurable anti detection measures:

- Successful result caching, with a customizable maximum and TTL
- Request cooldown (similar to rate limiting evasion)
- Proxy support

### Testing

To run the unit test(s), execute the following commands, depending 
on your operating system:

Windows:
- `(py/python) -m pytest tests`

Linux / macOS:
- `python3 -m pytest tests`

### Updates

hashes.com could patch this tool at any time. In the event that they do,
there's no guarantee I'll update this tool to bypass whatever measures they
put into place.
