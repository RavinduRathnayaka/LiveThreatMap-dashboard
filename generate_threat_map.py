import requests
import json
import random
import datetime
import shodan
import os
import re

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")

OUTPUT_SVG_FILENAME = "threat-map.svg"
SHODAN_QUERY = "has_vuln:true"
NUMBER_OF_RESULTS_TO_FETCH = 200
IPS_PER_CONTINENT = 10

SVG_WIDTH = 2000
SVG_HEIGHT = 1280


CONTINENT_TARGETS = {
    "North America": (41.8781, -87.6298),  # Chicago, USA
    "Europe": (50.1109, 8.6821),          # Frankfurt, Germany
    "Asia": (22.3193, 80.1694),         # Hong Kong
    "South America": (-23.5505, -46.6333), # São Paulo, Brazil
    "Africa": (6.5244, 3.3792),           # Lagos, Nigeria
    "Oceania": (-33.8688, 151.2093)       # Sydney, Australia
}


COUNTRY_TO_CONTINENT = {
    'US': 'North America', 'CA': 'North America', 'MX': 'North America', 'GL': 'North America', 'GT': 'North America', 'CR': 'North America', 'PA': 'North America',
    'AR': 'South America', 'BR': 'South America', 'BO': 'South America', 'CL': 'South America', 'CO': 'South America', 'EC': 'South America', 'PY': 'South America', 'PE': 'South America', 'UY': 'South America', 'VE': 'South America',
    'AL': 'Europe', 'AD': 'Europe', 'AM': 'Europe', 'AT': 'Europe', 'BY': 'Europe', 'BE': 'Europe', 'BA': 'Europe', 'BG': 'Europe', 'CH': 'Europe', 'CY': 'Europe', 'CZ': 'Europe', 'DE': 'Europe', 'DK': 'Europe', 'EE': 'Europe', 'ES': 'Europe', 'FI': 'Europe', 'FR': 'Europe', 'GB': 'Europe', 'GE': 'Europe', 'GR': 'Europe', 'HR': 'Europe', 'HU': 'Europe', 'IE': 'Europe', 'IS': 'Europe', 'IT': 'Europe', 'LT': 'Europe', 'LU': 'Europe', 'LV': 'Europe', 'MC': 'Europe', 'MK': 'Europe', 'MT': 'Europe', 'NO': 'Europe', 'NL': 'Europe', 'PL': 'Europe', 'PT': 'Europe', 'RO': 'Europe', 'RS': 'Europe', 'RU': 'Europe', 'SE': 'Europe', 'SI': 'Europe', 'SK': 'Europe', 'SM': 'Europe', 'UA': 'Europe', 'VA': 'Europe',
    'CN': 'Asia', 'HK': 'Asia', 'IN': 'Asia', 'ID': 'Asia', 'IR': 'Asia', 'IQ': 'Asia', 'JP': 'Asia', 'KG': 'Asia', 'KH': 'Asia', 'KP': 'Asia', 'KR': 'Asia', 'KZ': 'Asia', 'LA': 'Asia', 'LK': 'Asia', 'MM': 'Asia', 'MN': 'Asia', 'MY': 'Asia', 'NP': 'Asia', 'PH': 'Asia', 'PK': 'Asia', 'SA': 'Asia', 'SG': 'Asia', 'TH': 'Asia', 'TJ': 'Asia', 'TM': 'Asia', 'TR': 'Asia', 'TW': 'Asia', 'UZ': 'Asia', 'VN': 'Asia', 'AE': 'Asia', 'IL': 'Asia', 'QA': 'Asia', 'OM': 'Asia',
    'AU': 'Oceania', 'NZ': 'Oceania', 'FJ': 'Oceania', 'PG': 'Oceania',
    'DZ': 'Africa', 'AO': 'Africa', 'BW': 'Africa', 'BI': 'Africa', 'CM': 'Africa', 'CF': 'Africa', 'TD': 'Africa', 'CG': 'Africa', 'CD': 'Africa', 'DJ': 'Africa', 'EG': 'Africa', 'GQ': 'Africa', 'ET': 'Africa', 'GA': 'Africa', 'GM': 'Africa', 'GH': 'Africa', 'GN': 'Africa', 'KE': 'Africa', 'LS': 'Africa', 'LR': 'Africa', 'LY': 'Africa', 'MG': 'Africa', 'MW': 'Africa', 'ML': 'Africa', 'MR': 'Africa', 'MA': 'Africa', 'MZ': 'Africa', 'NA': 'Africa', 'NE': 'Africa', 'NG': 'Africa', 'RW': 'Africa', 'SN': 'Africa', 'SL': 'Africa', 'SO': 'Africa', 'ZA': 'Africa', 'SS': 'Africa', 'SD': 'Africa', 'TZ': 'Africa', 'TG': 'Africa', 'TN': 'Africa', 'UG': 'Africa', 'ZM': 'Africa', 'ZW': 'Africa',
}

ATTACK_COLORS = ["#00ff00", "#ff00ff", "#00ffff", "#ffea00", "#ff6600"]
TEXT_COLOR = "#cccccc"
LIST_BG_COLOR = "#1a1a1a"

def find_background_svg():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(script_dir, "map.svg")
    if os.path.exists(path):
        print(f"Found background SVG: {path}")
        return path
    print("Warning: No 'map.svg' found in the root directory.")
    return None

def get_ips_from_shodan():
    if not SHODAN_API_KEY:
        print("Error: SHODAN_API_KEY environment variable not set.")
        return {}
    print("Fetching and sorting IPs from Shodan by continent...")
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.search(SHODAN_QUERY, limit=NUMBER_OF_RESULTS_TO_FETCH)
        continent_ips = { name: [] for name in CONTINENT_TARGETS.keys() }
        
        for result in results['matches']:
            country_code = result.get('location', {}).get('country_code')
            continent = COUNTRY_TO_CONTINENT.get(country_code)
            
            if continent and len(continent_ips[continent]) < IPS_PER_CONTINENT:
                vulns = result.get('vulns', {})
                cve = list(vulns.keys())[0] if vulns else 'N/A' 
                
                threat_data = {
                    'ip': result['ip_str'],
                    'port': result['port'],
                    'cve': cve,
                    'continent': continent
                }
                continent_ips[continent].append(threat_data)

        print("IP distribution found:")
        for continent, threats in continent_ips.items():
            if threats: print(f" - {continent}: {len(threats)} threats")
        return continent_ips
    except shodan.APIError as e:
        print(f"Error querying Shodan: {e}")
        return {}

def get_geolocations_batch(ips):
    if not ips: return []
    print(f"Geolocating {len(ips)} IPs using the batch API...")
    try:
        response = requests.post("http://ip-api.com/batch?fields=lat,lon,country,query,status", json=ips, timeout=15)
        response.raise_for_status()
        return [item for item in response.json() if item.get("status") == "success"]
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"Error during batch geolocation: {e}")
        return []

def latlon_to_svg(lat, lon):

    SCALE_X = 2000 / 360.0
    SCALE_Y = 1280 / 180.0
    
    X_OFFSET = -42.0765
    Y_OFFSET = 191.8033

    x = (lon + 180) * SCALE_X + X_OFFSET
    y = (lat * -1 + 90) * SCALE_Y + Y_OFFSET
    
    return x, y


def generate_svg(attack_data_by_continent, svg_base_content):
    if not svg_base_content:
        svg_base_content = f'<svg width="{SVG_WIDTH}" height="{SVG_HEIGHT}" viewBox="0 0 {SVG_WIDTH} {SVG_HEIGHT}" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><rect width="100%" height="100%" fill="#0a0a0a"/>\n</svg>'
    

    svg_base_content = re.sub(r'(<path id="outline".*?style=")(.*?)(".*?>)', r'\1fill: #000000; fill-opacity: 1;\2\3', svg_base_content, flags=re.DOTALL)
    svg_base_content = re.sub(r'(<path id="boundaries".*?style=")(.*?)(".*?>)', r'\1stroke: #00ff00; stroke-width: 1px; fill: none;\2\3', svg_base_content, flags=re.DOTALL)

    injection_svg = ''
    injection_svg += f"""
    <style>
        .attack-dot, .origin-dot {{ filter: url(#glow); }}
        .target-dot {{ filter: url(#glow); animation: pulse 2.5s ease-in-out infinite; }}
        .text {{ font-family: monospace; fill: {TEXT_COLOR}; font-size: 24px; }}
        @keyframes pulse {{ 0% {{ r: 6; opacity: 1; }} 50% {{ r: 12; opacity: 0.7; }} 100% {{ r: 6; opacity: 1; }} }}
    </style>"""
    
    list_width = 500
    list_x = SVG_WIDTH - list_width - 40
    list_y = 40
    list_height = 280

    injection_svg += f"""
    <defs>
        <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="5" result="coloredBlur"/><feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <clipPath id="list-clip">
            <rect x="{list_x + 25}" y="{list_y + 60}" width="{list_width - 50}" height="{list_height}"/>
        </clipPath>
    </defs>"""
    
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    injection_svg += f'<text x="40" y="80" class="text" font-size="44px">LIVE THREAT MAP</text>'
    injection_svg += f'<text x="40" y="115" class="text" font-size="24px" fill="#888888">Last updated: {timestamp}</text>'

    all_attacks = [attack for attacks in attack_data_by_continent.values() for attack in attacks]

    if all_attacks:
        countries = sorted(list(set(attack.get('country') for attack in all_attacks if attack.get('country'))))
        injection_svg += f'<text x="40" y="160" class="text" font-size="22px" font-weight="bold" fill="#dddddd">Threat Origins:</text>'
        countries_per_line = 6
        country_chunks = [countries[i:i + countries_per_line] for i in range(0, len(countries), countries_per_line)]
        line_y_start = 190
        line_height = 28
        for index, chunk in enumerate(country_chunks):
            line_text = ", ".join(chunk)
            current_y = line_y_start + (index * line_height)
            injection_svg += f'<text x="40" y="{current_y}" class="text" font-size="18px" fill="#aaaaaa">{line_text}</text>'

    for lat, lon in CONTINENT_TARGETS.values():
        target_x, target_y = latlon_to_svg(lat, lon)
        injection_svg += f'<circle cx="{target_x}" cy="{target_y}" r="5" fill="#00ff99" class="target-dot"/>'
    
    if all_attacks:
        num_items = len(all_attacks)
        item_height = 28
        total_scroll_height = num_items * item_height
        animation_duration = num_items * 1.5
        injection_svg += f'<rect x="{list_x}" y="{list_y}" width="{list_width}" height="350" fill="{LIST_BG_COLOR}" fill-opacity="0.7" rx="15"/>'
        injection_svg += f'<text x="{list_x + 25}" y="{list_y + 45}" class="text" font-size="28px" font-weight="bold">RECENT THREATS</text>'
        injection_svg += f'<g clip-path="url(#list-clip)"><g>'
        sorted_attack_data = sorted(all_attacks, key=lambda x: x['ip'])
        for i, attack in enumerate(sorted_attack_data * 2):
            country = attack.get('country', 'Unknown')
            port = attack.get('port', 'N/A')
            cve = attack.get('cve', 'N/A')
            ip_text = f"{attack['ip']}:{port:<5} - {cve:<15} - {country}"
            text_y = list_y + 85 + (i * item_height)
            injection_svg += f'<text x="{list_x + 25}" y="{text_y}" class="text">{ip_text}</text>'
        injection_svg += (f'<animateTransform attributeName="transform" type="translate" from="0 0" to="0 -{total_scroll_height}" '
                f'dur="{animation_duration}s" repeatCount="indefinite"/>')
        injection_svg += f'</g></g>'

    path_counter = 0
    continent_names = list(CONTINENT_TARGETS.keys())
    for continent, attacks in attack_data_by_continent.items():
        for attack in attacks:
            if random.random() < 0.5:
                other_continents = [c for c in continent_names if c != continent]
                target_continent = random.choice(other_continents) if other_continents else continent
            else:
                target_continent = continent

            target_lat, target_lon = CONTINENT_TARGETS[target_continent]
            target_x, target_y = latlon_to_svg(target_lat, target_lon)
            source_x, source_y = latlon_to_svg(attack["lat"], attack["lon"])
            color = random.choice(ATTACK_COLORS)
            ctrl_x = (source_x + target_x) / 2 + (target_y - source_y) * random.uniform(0.2, 0.5)
            ctrl_y = (source_y + target_y) / 2 - (target_x - source_x) * random.uniform(0.2, 0.5)
            path_data = f"M{source_x},{source_y} Q{ctrl_x},{ctrl_y} {target_x},{target_y}"
            path_id = f"path{path_counter}"
            
            injection_svg += f'''
                <circle cx="{source_x}" cy="{source_y}" r="4" fill="{color}" class="origin-dot">
                    <animate attributeName="opacity" values="0.5;1;0.5" dur="2s" repeatCount="indefinite" />
                </circle>
            '''
            
            injection_svg += f'<path d="{path_data}" stroke="#ff0000" stroke-opacity="0.15" stroke-width="1" fill="none"/>'
            
            injection_svg += f'<path id="{path_id}" d="{path_data}" stroke="none" fill="none"/>'
            
            delay = round(random.uniform(0, 5), 2)
            duration = round(random.uniform(3, 6), 2)
            
            num_particles = 8
            for i in range(num_particles):
                particle_radius = max(1, 5 - i * 0.5)
                particle_opacity = max(0.2, 1.0 - i * 0.1)
                particle_delay = delay + i * 0.04

                injection_svg += (
                    f'<circle r="{particle_radius}" fill="{color}" opacity="{particle_opacity}" class="attack-dot">'
                    f'<animateMotion dur="{duration}s" repeatCount="indefinite" begin="{particle_delay}s" calcMode="spline" keyTimes="0;1" keySplines="0.4 0 0.2 1">'
                    f'<mpath xlink:href="#{path_id}"/></animateMotion></circle>'
                )
            path_counter += 1

    final_svg = svg_base_content.replace('</svg>', injection_svg + '\n</svg>')
    return final_svg

def main():
    print("Starting threat map generation...")
    
    threats_by_continent = get_ips_from_shodan()
    if not any(threats_by_continent.values()):
        print("No threats found from Shodan to process. Exiting.")
        return
        
    all_threats_flat = [threat for threat_list in threats_by_continent.values() for threat in threat_list]
    all_ips_flat = [threat['ip'] for threat in all_threats_flat]
    
    geolocated_data = get_geolocations_batch(all_ips_flat)
    print(f"Successfully geolocated {len(geolocated_data)} IPs.")
    if not geolocated_data:
        print("Could not geolocate any IPs. Exiting.")
        return

    geo_map = {item['query']: {'lat': item['lat'], 'lon': item['lon'], 'country': item['country']} for item in geolocated_data}
    
    final_threat_data_by_continent = { name: [] for name in CONTINENT_TARGETS.keys() }
    for threat in all_threats_flat:
        if threat['ip'] in geo_map:
            threat.update(geo_map[threat['ip']])
            final_threat_data_by_continent[threat['continent']].append(threat)
    
    svg_path = find_background_svg()
    svg_base_content = None
    if svg_path:
        try:
            with open(svg_path, "r", encoding="utf-8") as f:
                svg_base_content = f.read()
            if 'xmlns:xlink' not in svg_base_content:
                svg_base_content = svg_base_content.replace('<svg', '<svg xmlns:xlink="http://www.w3.org/1999/xlink"', 1)
        except IOError as e:
            print(f"Error reading SVG base file: {e}")
    
    svg_content = generate_svg(final_threat_data_by_continent, svg_base_content)
    
    try:
        with open(OUTPUT_SVG_FILENAME, "w", encoding="utf-8") as f:
            f.write(svg_content)
        print(f"Successfully generated and saved '{OUTPUT_SVG_FILENAME}'")
    except IOError as e:
        print(f"Error writing SVG file: {e}")

if __name__ == "__main__":
    main()

