import requests
import socket
import ssl
import whois
import time
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from urllib.parse import urlparse
from threading import Thread, Event
from concurrent.futures import ThreadPoolExecutor, as_completed

console = Console()
stop_event = Event()

def clear_screen():
    os.system('clear')

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def get_ip_address(url):
    try:
        return socket.gethostbyname(url)
    except socket.gaierror:
        return "Not Available"

def get_ssl_info(url):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((url, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=url) as ssock:
                cert = ssock.getpeercert()
                return {
                    "SSL Valid From": cert['notBefore'],
                    "SSL Valid Until": cert['notAfter']
                }
    except Exception as e:
        return {"Error": str(e)}

def get_http_status(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code
    except requests.exceptions.RequestException as e:
        return str(e)

def get_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        return {
            "HSTS": headers.get('Strict-Transport-Security', 'Not Available'),
            "CSP": headers.get('Content-Security-Policy', 'Not Available'),
            "X-Frame": headers.get('X-Frame-Options', 'Not Available'),
            "X-Content-Type": headers.get('X-Content-Type-Options', 'Not Available'),
            "XSS Protection": headers.get('X-XSS-Protection', 'Not Available'),
            "Referrer Policy": headers.get('Referrer-Policy', 'Not Available'),
            "Feature Policy": headers.get('Feature-Policy', 'Not Available')
        }
    except requests.exceptions.RequestException as e:
        return {"Error": str(e)}

def get_admin_panel_urls(url):
    common_paths = [
        "/login", "/administrator", "/wp-admin", "/admin", "/panel",
        "/admin.php", "/cp", "/admin/login"
    ]
    return [f"https://{url}{path}" for path in common_paths]

def get_server_info(url):
    try:
        response = requests.get(url, timeout=5)
        return response.headers.get('Server', 'Not Available')
    except requests.exceptions.RequestException as e:
        return str(e)

def get_x_powered_by(url):
    try:
        response = requests.get(url, timeout=5)
        return response.headers.get('X-Powered-By', 'Not Available')
    except requests.exceptions.RequestException as e:
        return str(e)

def get_server_location(url):
    try:
        ip = socket.gethostbyname(url)
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = response.json()
        return f"{data.get('city', 'Not Available')}, {data.get('region', 'Not Available')}, {data.get('country', 'Not Available')}"
    except Exception as e:
        return str(e)

def get_whois_info(url):
    try:
        w = whois.whois(url)
        return str(w)
    except Exception as e:
        return str(e)

def get_robots_txt(url):
    try:
        response = requests.get(f"https://{url}/robots.txt", timeout=5)
        return response.text
    except requests.exceptions.RequestException as e:
        return str(e)

def get_sitemap(url):
    try:
        response = requests.get(f"https://{url}/sitemap.xml", timeout=5)
        return response.text
    except requests.exceptions.RequestException as e:
        return str(e)

def get_dns_records(url):
    try:
        response = requests.get(f"https://dns.google/resolve?name={url}&type=A", timeout=5)
        data = response.json()
        return "\n".join([f"{record['type']}: {record['data']}" for record in data['Answer']])
    except Exception as e:
        return str(e)

def get_subdomains(url):
    try:
        response = requests.get(f"https://securitytrails.com/domain/{url}/subdomains", timeout=5)
        data = response.json()
        return "\n".join(data['subdomains'])
    except Exception as e:
        return str(e)

def get_technologies(url):
    try:
        response = requests.get(f"https://builtwith.com/reports/{url}", timeout=5)
        data = response.json()
        return "\n".join([tech['name'] for tech in data['result']['technologies']])
    except Exception as e:
        return str(e)

def get_cookies(url):
    try:
        response = requests.get(url, timeout=5)
        cookies = response.cookies
        return "\n".join([f"{cookie.name}: {cookie.value}" for cookie in cookies])
    except requests.exceptions.RequestException as e:
        return str(e)

def get_redirects(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        return "\n".join([f"{hist.url}" for hist in response.history])
    except requests.exceptions.RequestException as e:
        return str(e)

def save_file(content, filename):
    with open(filename, 'w') as file:
        file.write(content)
    return filename, sum(1 for line in content.splitlines())

def fetch_data(url):
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(get_ip_address, url): "IP Address",
            executor.submit(get_ssl_info, url): "SSL Info",
            executor.submit(get_http_status, f"https://{url}"): "HTTP Status",
            executor.submit(get_security_headers, f"https://{url}"): "Security Headers",
            executor.submit(get_admin_panel_urls, url): "Admin Panel URLs",
            executor.submit(get_server_info, f"https://{url}"): "Server Info",
            executor.submit(get_x_powered_by, f"https://{url}"): "X-Powered-By",
            executor.submit(get_server_location, url): "Server Location",
            executor.submit(get_whois_info, url): "WHOIS Info",
            executor.submit(get_robots_txt, url): "Robots.txt",
            executor.submit(get_sitemap, url): "Sitemap",
            executor.submit(get_dns_records, url): "DNS Records",
            executor.submit(get_subdomains, url): "Subdomains",
            executor.submit(get_technologies, url): "Technologies",
            executor.submit(get_cookies, f"https://{url}"): "Cookies",
            executor.submit(get_redirects, f"https://{url}"): "Redirects"
        }
        results = {}
        for future in as_completed(futures):
            category = futures[future]
            results[category] = future.result()
        return results

def display_results(url):
    parsed_url = urlparse(url)
    url = parsed_url.netloc

    data = fetch_data(url)

    ip_address = data["IP Address"]
    ssl_info = data["SSL Info"]
    http_status = data["HTTP Status"]
    security_headers = data["Security Headers"]
    admin_panel_urls = data["Admin Panel URLs"]
    server_info = data["Server Info"]
    x_powered_by = data["X-Powered-By"]
    server_location = data["Server Location"]
    whois_info = data["WHOIS Info"]
    robots_txt = data["Robots.txt"]
    sitemap = data["Sitemap"]
    dns_records = data["DNS Records"]
    subdomains = data["Subdomains"]
    technologies = data["Technologies"]
    cookies = data["Cookies"]
    redirects = data["Redirects"]

    robots_txt_file, robots_txt_lines = save_file(robots_txt, 'robots.txt')
    sitemap_file, sitemap_lines = save_file(sitemap, 'sitemap.xml')

    table = Table(title=f"Website Scan Results: [bold cyan]{url}[/bold cyan]", style="cyan")
    table.add_column("Category", style="green", no_wrap=True)
    table.add_column("Details", style="magenta")

    table.add_row("IP Address", ip_address)
    table.add_row("SSL Valid From", ssl_info.get('SSL Valid From', 'Not Available'))
    table.add_row("SSL Valid Until", ssl_info.get('SSL Valid Until', 'Not Available'))
    table.add_row("HTTP Status", str(http_status))

    for header, value in security_headers.items():
        table.add_row(header, value)

    table.add_row("Server", server_info)
    table.add_row("X-Powered-By", x_powered_by)
    table.add_row("Server Location", server_location)
    table.add_row("WHOIS Info", whois_info)
    table.add_row("Robots.txt", f"Saved to {robots_txt_file} ({robots_txt_lines} lines)")
    table.add_row("Sitemap", f"Saved to {sitemap_file} ({sitemap_lines} lines)")
    table.add_row("DNS Records", dns_records)
    table.add_row("Subdomains", subdomains)
    table.add_row("Technologies", technologies)
    table.add_row("Cookies", cookies)
    table.add_row("Redirects", redirects)
    table.add_row("Admin Panel URLs", "\n".join(admin_panel_urls))

    console.print(Panel(table, title="[bold blue]Scan Results[/bold blue]", border_style="blue"))
    console.print(Panel("By sentinelzxofc", style="bold red", border_style="red"))
    stop_event.set()

def loading_animation():
    with Live(console=console, screen=False) as live:
        while not stop_event.is_set():
            live.update(Text("Loading...", style="bold green"))
            time.sleep(0.5)
            live.update(Text("Loading...", style="bold yellow"))
            time.sleep(0.5)

if __name__ == "__main__":
    clear_screen()
    console.print(Panel(
        """
==================================================
=                                                =
=    _____ _ _   _____       _____               =
=   / ____(_) | |  __ \     / ____|              =
=  | (___  _| |_| |__) |___| (___   ___ __ _ _ __=
=   \___ \| | __|  ___/ _ \\___ \ / __/ _` | '_ \=
=  ____) | | |_| |  | (_) |___) | (_| (_| | | | |=
= |_____/|_|\__|_|   \___/_____/ \___\__,_|_| |_|=
=                                                =
=               SiteScanner                      =
=                                                =
=  https://github.com/sentinelzxofc/SiteScanner  =
=  by: sentinelzxofc                             =
=                                                =
==================================================
        """,
        style="bold magenta",
        border_style="bold magenta"
    ))
    url = input("Enter website URL (with http/https): ")
    if not is_valid_url(url):
        console.print("Invalid URL. Please enter a valid URL.", style="bold red")
    else:
        loading_thread = Thread(target=loading_animation)
        loading_thread.start()
        try:
            display_results(url)
        except Exception as e:
            console.print(f"An error occurred: {str(e)}", style="bold red")
        finally:
            stop_event.set()
            loading_thread.join()
