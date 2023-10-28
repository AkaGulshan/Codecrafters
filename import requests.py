from flask import Flask, render_template, request, redirect, url_for, Response, flash
import requests
import ssl
import whois
from googleapiclient.discovery import build
import cv2
import numpy as np
from matplotlib import pyplot as plt
import base64
import io

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Function to fetch website traffic data from SimilarWeb
def get_website_traffic_data(url):
    # Your SimilarWeb API key
    api_key = 'YOUR_SIMILARWEB_API_KEY'
    endpoint = f"https://api.similarweb.com/v1/website/{url}/total-traffic-and-engagement"
    headers = {
        'User-Key': api_key
    }

    response = requests.get(endpoint, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return None

# Function to check if the website is indexed on Google using API key and CSE ID
def is_indexed_on_google(query, api_key, cse_id):
    try:
        service = build("customsearch", "v1", developerKey=api_key)
        result_set = service.cse().list(q=query, cx=cse_id).execute()
        if 'items' in result_set:
            return True
        else:
            return False
    except:
        return False

# Placeholder for authority analysis
def authority_analysis(url):
    return True

# Function to fetch and store the HTML content of the website
def get_html_content(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return None
    except:
        return None

# Google Safe Browsing API integration
def check_phishing(url):
    try:
        # Initialize Google Safe Browsing API
        API_KEY = 'AIzaSyDX3BrKMZsUudbKZgL-hn4AGqKie_qqhqE'
        ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
        PLATFORM_TYPES = ["ANY_PLATFORM"]
        THREAT_ENTRY_TYPES = ["URL"]
        client_id = '624375346639-csrosvlqi9svjj8gf64atceovr2nukgr.apps.googleusercontent.com'

        request_body = {
            "client": {
                "clientId": client_id,
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": PLATFORM_TYPES,
                "threatEntryTypes": THREAT_ENTRY_TYPES,
                "threatEntries": [{"url": url}],
            },
        }

        response = requests.post(
            ENDPOINT,
            params={"key": API_KEY},
            json=request_body
        )

        if response.status_code == 200:
            threat_matches = response.json().get("matches", [])
            if threat_matches:
                return "Phishing"
            else:
                return "Safe"
        else:
            return "Error"
    except Exception as e:
        return "Error"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = {
        "ssl": None,
        "url": "",
        "traffic_data": None,
        "traffic_graph": None,
        "website_html": None,
        "whois_data": None,
        "phishing_status": None
    }

    if request.method == 'POST':
        url = request.form['url']
        result["url"] = url

        # SSL Analysis
        try:
            context = ssl.create_default_context()
            with requests.get(url, verify=True) as response:
                result["ssl"] = True
        except:
            result["ssl"] = False

        # Check if the website is indexed on Google using API key and CSE ID
        google_api_key = 'AIzaSyC3LMKkX-wUhSE8y9HGZ4FGtvfp8EOtSTk'
        search_engine_id = 'e07a6b0c2617341fd'
        indexed = is_indexed_on_google(url, google_api_key, search_engine_id)
        result["indexed"] = indexed

        # Get Website Traffic Data
        traffic_data = get_website_traffic_data(url)
        if traffic_data:
            result["traffic_data"] = traffic_data

            # Generate a line graph from traffic data
            if 'visits' in traffic_data and 'dates' in traffic_data:
                dates = traffic_data['dates']
                visits = traffic_data['visits']
                plt.plot(dates, visits)
                plt.xlabel('Date')
                plt.ylabel('Visits')
                plt.title('Website Traffic Over Time')

                # Save the graph as an image and encode it in base64
                buffer = io.BytesIO()
                plt.savefig(buffer, format='png')
                traffic_graph_data = base64.b64encode(buffer.getvalue()).decode()
                result["traffic_graph"] = f'data:image/png;base64,{traffic_graph_data}'

        # Fetch and store the HTML content of the website if it is indexed on Google
        if indexed:
            result["website_html"] = url_for('view_html', url=url)

        # Retrieve Whois data
        try:
            whois_data = whois.whois(url)
            result["whois_data"] = whois_data
        except whois.parser.PywhoisError as e:
            result["whois_data"] = str(e)

        # Check for phishing using Google Safe Browsing API
        phishing_status = check_phishing(url)
        result["phishing_status"] = phishing_status

    return render_template('index.html', result=result)


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/team')
def team():
    return render_template('team.html')

@app.route('/roadmap')
def roadmap():
    return render_template('roadmap.html')

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/checkurl')
def checkurl():
    return render_template('checkurl.html')

@app.route('/view_html')
def view_html():
    url = request.args.get('url')

    if not url:
        return "URL parameter is missing."

    try:
        response = requests.get(url)
        if response.status_code == 200:
            html_content = response.text
            return html_content  # Return HTML code directly
        else:
            return "Failed to retrieve HTML data."
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)

