from django.shortcuts import render
from ipware import get_client_ip
import requests

proxy_headers = ['CLIENT_IP', 'FORWARDED', 'FORWARDED_FOR',
                 'FORWARDED_FOR_IP', 'VIA', 'X_FORWARDED',
                 'X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'HTTP_FORWARDED',
                 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED_FOR_IP', 'HTTP_PROXY_CONNECTION',
                 'HTTP_VIA', 'HTTP_X_FORWARDED', 'HTTP_X_FORWARDED_FOR']


# Create your views here.
def index(request):
    template = "index.html"
    context = {}
    proxy_headers_list = []

    # Get IP
    ip, is_routable = get_client_ip(request)
    context["ip"] = ip

    # Check proxy and headers
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

    # Check for VPN
    context["VPN"] = False

    # Check for TOR
    # raw_data = requests.get('https://check.torproject.org/exit-addresses')
    # data = list(raw_data.text.splitlines())
    with open("tor_ips.txt", 'r') as file:
        ips = file.read().splitlines()
        print(ips)
        for tor_ip in ips:
            if ip == tor_ip:
                context["TOR"] = True
                break
            else:
                context["TOR"] = False

    # Check for being on cite before
    context["was_here"] = True

    return render(request, template, context)
