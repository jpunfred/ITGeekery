import json
import re
import requests
from urllib.parse import quote_plus
import logging
import feedparser
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from .forms import SignUpForm, ProfileUpdateForm
from .models import Profile

# Configure logging
logger = logging.getLogger(__name__)

def signup(request):
    """Handles user signup."""
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('dashboard')
        else:
            logger.error("Signup form errors: %s", form.errors)
    else:
        form = SignUpForm()
    return render(request, 'dashboard/signup.html', {'form': form})
#dashboard.html
@login_required
def dashboard(request):
    """View that fetches CVEs, network status, and news feed for the dashboard."""
    profile = Profile.objects.filter(user=request.user).first()
    if not profile:
        logger.error("Profile not found for user: %s", request.user.username)
        return render(request, 'dashboard/dashboard.html', {'message': 'Profile not found.'})

    if not profile.keywords:
        return render(request, 'dashboard/dashboard.html', {'message': 'No keywords specified in your profile.'})

    cves = fetch_cves_for_keywords(profile.keywords)
    network_status = fetch_network_status()
    news_feed = fetch_news()

    return render(request, 'dashboard/dashboard.html', {
        
        'cves': cves[:14],
        'network_status': network_status,
        'news_feed': news_feed,
        'profile': profile,
    })
#CVE Table
def fetch_cves_for_keywords(keywords):
    cves = []
    for keyword in keywords.split(','):
        response = fetch_cves(keyword.strip())
        if response.status_code == 200:
            data = response.json()
            process_cve_data(data, cves, keyword)
        else:
            logger.error("Failed to fetch CVE data for keyword '%s': HTTP %s", keyword, response.status_code)
    cves.sort(key=lambda x: x['published_date'], reverse=True)
    return cves
# Grabs from NIST API
def fetch_cves(keyword):
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote_plus(keyword)}&resultsPerPage=20'
    return requests.get(url)
# Parses the CVE data and adds it to the cves list
def process_cve_data(data, cves, keyword):
    for item in data.get('vulnerabilities', []):
        cve_data = item.get('cve', {})
        cve_id = cve_data.get('id', 'N/A')
        published = cve_data.get('published', 'N/A')[:10]
        cves.append({
            'cve_id': cve_id,
            'keyword': keyword,
            'published_date': published
        })
# Pings host names to capture response time
def fetch_network_status():
    hosts = [
        "http://google.com", "https://wtamu.edu", "http://microsoft.com", "http://xbox.com", 
        "http://apple.com", "http://icloud.com", "http://www.canyontx.gov", "http://github.com",
        "http://itgeekery.tech", "http://www.twitter.com", "http://www.facebook.com", 
        "http://www.gmail.com", "http://www.proton.me", "http://www.amazon.com",
    ]
    results = []
    for host in hosts:
        result = check_host(host)
        results.append(result)
    return results
# Checks host name and returns response time
def check_host(host):
    try:
        response = requests.get(host, timeout=5)
        time_ms = response.elapsed.total_seconds() * 1000  # in milliseconds
        color = 'lightgreen' if time_ms <= 30 else \
                'yellow' if time_ms <= 100 else \
                'orange' if time_ms <= 200 else \
                'lightsalmon' if time_ms <= 500 else \
                'purple'
        return {'host': host, 'time': f"{time_ms:.2f} ms", 'color': color}
    except requests.exceptions.RequestException:
        return {'host': host, 'time': "Offline or no response", 'color': "lightsalmon"}
# account.html
@login_required
def account_management(request):
    """Manages account information including profile updates and password changes."""
    p_form = ProfileUpdateForm(request.POST or None, instance=request.user)
    password_form = PasswordChangeForm(request.user, request.POST or None)

    if request.method == 'POST':
        if 'update_profile' in request.POST and p_form.is_valid():
            p_form.save()
            return redirect('dashboard')
        if 'change_password' in request.POST and password_form.is_valid():
            password_form.save()
            update_session_auth_hash(request, password_form.user)
            return redirect('dashboard')

    return render(request, 'dashboard/account.html', {'p_form': p_form, 'password_form': password_form})
# Fetches news feed from RSS feed
def fetch_news():
    feeds = [
        'techradar.com/rss', 'lux.camera/rss', 'https://www.reddit.com/r/ITManagers/new/.rss',
        'https://www.bleepingcomputer.com/feed/', 'http://feeds.feedburner.com/ServeTheHome',
        'https://stackoverflow.blog/feed/atom/', 'http://www.osnews.com/files/recent.xml',
        'http://feeds.arstechnica.com/arstechnica/index?format=xml',
    ]
    news_items = []
    for feed_url in feeds:
        news = parse_news_feed(feed_url)
        news_items.extend(news)
    news_items.sort(key=lambda x: x['published'], reverse=True)
    return news_items[:25]
# Parses RSS feed and returns cleaner display for title and summary
def parse_news_feed(feed_url):
    try:
        parsed_feed = feedparser.parse(feed_url)
        return [
            format_news_entry(entry)
            for entry in parsed_feed.entries[:7]
        ]
    except Exception as e:
        logger.error("Error fetching or parsing feed '%s': %s", feed_url, str(e))
        return []
# Formats news entry for display
def format_news_entry(entry):
    image_url = find_image_in_entry(entry)
    cleaned_description = re.sub(r'<[^>]+>', '', entry.get('description', ''))
    snippet = (cleaned_description[:500] + '...') if len(cleaned_description) > 500 else cleaned_description
    return {
        'title': entry.title,
        'link': entry.link,
        'published': entry.published,
        'image_url': image_url,
        'snippet': snippet
    }
# If there's an image in the entry, display, otherwise return None
def find_image_in_entry(entry):
    if 'media_content' in entry:
        for media in entry.media_content:
            if media.get('medium') == 'image':
                return media['url']
    if 'enclosures' in entry:
        for enclosure in entry.enclosures:
            if enclosure.type.startswith('image'):
                return enclosure.href
    if 'description' in entry:
        img_search = re.search(r'<img src="(.*?)"', entry.description)
        if img_search:
            return img_search.group(1)
    return None
