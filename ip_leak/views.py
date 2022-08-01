import asyncio
import pyppeteer
from django.http import HttpResponse
from django.shortcuts import render
from ipware import get_client_ip
from requests_html import AsyncHTMLSession
import re

proxy_headers = ['CLIENT_IP', 'FORWARDED', 'FORWARDED_FOR',
                 'FORWARDED_FOR_IP', 'VIA', 'X_FORWARDED',
                 'X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'HTTP_FORWARDED',
                 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED_FOR_IP', 'HTTP_PROXY_CONNECTION',
                 'HTTP_VIA', 'HTTP_X_FORWARDED', 'HTTP_X_FORWARDED_FOR']


async def get_vpn(ip):
    session = AsyncHTMLSession()
    browser = await pyppeteer.launch({
        'ignoreHTTPSErrors': True,
        'headless': True,
        'handleSIGINT': False,
        'handleSIGTERM': False,
        'handleSIGHUP': False
    }, args=['--no-sandbox'])
    session._browser = browser
    r = await session.get(f'https://qlavs.github.io/ipredir/?addr={ip}')
    await r.html.arender(sleep=2)
    data = r.html.html
    print(data)
    try:
        status = re.search('"vpn":(.*),"tor', data)
        await browser.close()
        await session.close()
        return status.group(1).capitalize()
    except:
        await browser.close()
        await session.close()
        return False


# Create your views here.
def index(request):
    template = "index.html"
    context = {}
    proxy_headers_list = []

    # - Get IP -
    ip, is_routable = get_client_ip(request)
    context["ip"] = ip

    # - Check proxy and headers -
    all_headers = dict(request.headers)
    for pr_header in proxy_headers:
        if pr_header in all_headers:
            proxy_headers_list.append(pr_header)

    if len(proxy_headers_list) > 0:
        context["proxy_headers"] = True
        context["proxy"] = True
        context["proxy_headers_list"] = proxy_headers_list
    else:
        context["proxy_headers"] = False
        context["proxy"] = False

    # - Check for VPN -
    # response = requests.get(f'https://ipqualityscore.com/api/json/ip/iWY48acUFG4aIun9wpZkIv8WpEeTycbp/{ip}')
    # status = response.json()["vpn"]
    # print(status)
    # loop = asyncio.get_event_loop()
    # loop.run_until_complete(asyncio.gather(*task))
    # loop.close()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(get_vpn(ip))
    context["VPN"] = result

    # - Check for TOR -
    # raw_data = requests.get('https://check.torproject.org/exit-addresses')
    # data = list(raw_data.text.splitlines())
    with open("tor_ips.txt", 'r') as file:
        ips = file.read().splitlines()
        for tor_ip in ips:
            if ip == tor_ip:
                context["TOR"] = True
                break
            else:
                context["TOR"] = False

    # - Check for being on cite before -
    cookie = request.COOKIES.get('was_here_before')
    if cookie is not None:
        context["was_here"] = cookie
        return render(request, template, context)
    else:
        print('First time on page')
        context["was_here"] = False
        response = render(request, template, context)
        response.set_cookie('was_here_before', True, max_age=365*24*60*60)
        return response


