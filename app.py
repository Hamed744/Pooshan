import os
import requests
from flask import Flask, Response, request, stream_with_context
from urllib.parse import urlparse, urljoin, urlunparse
import re
import random
import logging
import json # برای تبدیل دیکشنری پایتون به رشته JSON

app = Flask(__name__) # اصلاح: __name__ به جای name
SECRET_NAME_FOR_TARGET_URL = "TARGET_HF_SPACE_URL"
TARGET_URL_FROM_SECRET = os.environ.get(SECRET_NAME_FOR_TARGET_URL)
REQUEST_TIMEOUT = 45

# --- Logging Setup (حداقل لاگ ممکن) ---
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR) # فقط خطاهای Werkzeug را لاگ کن
# app.logger.setLevel(logging.CRITICAL + 1) # غیرفعال کردن کامل لاگ‌های اپلیکیشن Flask
# برای دیباگ می‌توانید این خط را کامنت کنید یا سطح را تغییر دهید
if not (os.environ.get('FLASK_DEBUG', '0') == '1' or os.environ.get('FLASK_ENV') == 'development'):
    app.logger.setLevel(logging.CRITICAL + 1)
else:
    app.logger.setLevel(logging.INFO) # لاگ در حالت دیباگ

print(f"APP_STARTUP: TARGET_URL_FROM_SECRET: {'SET' if TARGET_URL_FROM_SECRET else 'NOT SET'}")
if TARGET_URL_FROM_SECRET:
    print(f"APP_STARTUP: Target URL is '{TARGET_URL_FROM_SECRET[:20]}...'") # بخشی از URL برای تایید

COMMON_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
    # ... (سایر User-Agent ها)
]

SIMPLE_TEXT_REPLACEMENTS = {
    "Aya Vision": "تحلیل",
    "Chat with Aya": "چت🤖",
    "Visualize with Aya": "عکس",
    "Speak with Aya": "", # این مورد باعث مخفی شدن المان والدش می‌شود
    # ... (سایر جایگزینی‌های متن)
    "Gradio": "App", # مثال: جایگزینی کلمه Gradio
    "Built with Gradio": "" # حذف این عبارت
}

GRADIO_HIDE_CSS_STANDARD = """
<style>
  /* فوتر Gradio */
  .gradio-container .meta-footer, .gradio-container footer, div[class*="footer"], footer, a[href*="gradio.app"],
  /* دکمه Settings Gradio */
  .gradio-container button[id*="settings"], .gradio-container div[class*="settings-button"],
  a[href*="gradio.app/"], button[title*="Settings"], button[aria-label*="Settings"], div[data-testid*="settings"] {
    display: none !important;
    visibility: hidden !important;
    opacity: 0 !important;
    width: 0 !important;
    height: 0 !important;
    overflow: hidden !important;
    margin: 0 !important;
    padding: 0 !important;
    border: none !important;
    font-size: 0 !important;
    line-height: 0 !important;
  }
  /* کلاس برای مخفی کردن المان‌هایی که متن آنها با رشته خالی جایگزین شده */
  .gr-proxy-item-hidden-by-text {
    display: none !important;
    visibility: hidden !important;
  }
</style>
"""

def process_html_content_server_side(html_string):
    """فقط حذف‌های اولیه سمت سرور با Regex (بدون تزریق CSS در اینجا)."""
    processed_html = html_string
    # ... (کد مربوط به حذف با Regex شما) ...
    return processed_html

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']) # اصلاح: <path:path>
def proxy_request_handler(path):
    if not TARGET_URL_FROM_SECRET:
        app.logger.critical(f"CRITICAL: Secret '{SECRET_NAME_FOR_TARGET_URL}' is not set.")
        return "Proxy Configuration Error: Target URL secret is not configured.", 500

    base_target_url = TARGET_URL_FROM_SECRET.rstrip('/')
    # اطمینان از اینکه path با / شروع نمی‌شود اگر base_target_url خودش با / ختم شده
    target_full_url = urljoin(base_target_url + "/", path.lstrip('/'))
    if request.query_string:
        target_full_url += "?" + request.query_string.decode()
    
    app.logger.debug(f"Proxying request for path: /{path} to {target_full_url}")

    try:
        parsed_target_url_for_host = urlparse(TARGET_URL_FROM_SECRET)
        target_hostname = parsed_target_url_for_host.hostname
        user_agent_to_send = random.choice(COMMON_USER_AGENTS)
        
        excluded_incoming_headers = [
            'host', 'cookie', 'connection', 'upgrade-insecure-requests', 
            'if-none-match', 'if-modified-since', 'referer', 'x-hf-space-host',
            'content-length' # اجازه به requests برای محاسبه مجدد
        ]
        forward_headers = {key: value for key, value in request.headers.items() if key.lower() not in excluded_incoming_headers}
        forward_headers['User-Agent'] = user_agent_to_send
        forward_headers['Host'] = target_hostname
        forward_headers['Accept-Encoding'] = 'gzip, deflate, br'
        
        # مدیریت X-Forwarded-For
        if request.headers.getlist("X-Forwarded-For"):
            forward_headers["X-Forwarded-For"] = request.headers.getlist("X-Forwarded-For")[0] + ", " + request.remote_addr
        else:
            forward_headers["X-Forwarded-For"] = request.remote_addr
        
        # برای POST, PUT, etc.
        request_body = request.get_data() if request.method not in ['GET', 'HEAD', 'OPTIONS'] else None

        with requests.Session() as s:
            target_response = s.request(
                method=request.method,
                url=target_full_url,
                headers=forward_headers,
                data=request_body,
                stream=True, # مهم برای stream کردن پاسخ
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False # ریدایرکت‌ها را خودمان مدیریت می‌کنیم
            )

        # مدیریت ریدایرکت‌ها
        if 300 <= target_response.status_code < 400 and 'Location' in target_response.headers:
            location = target_response.headers['Location']
            # ... (کد مدیریت ریدایرکت شما، اطمینان از بازنویسی صحیح Location) ...
            # این بخش نیاز به بازبینی دقیق دارد تا Location به درستی به دامنه پروکسی بازنویسی شود
            parsed_location = urlparse(location)
            rewritten_location_header_val = location
            # اگر ریدایرکت نسبی است یا به همان هاست هدف است، آن را برای پروکسی بازنویسی کن
            if not parsed_location.scheme or parsed_location.hostname == target_hostname:
                # URL کامل ریدایرکت را بر اساس URL نهایی که requests به آن رسیده، بساز
                abs_target_redirect_url = urljoin(target_response.url, location)
                new_path_on_target = urlparse(abs_target_redirect_url).path
                new_query_on_target = urlparse(abs_target_redirect_url).query
                
                rewritten_location_path = new_path_on_target
                if new_query_on_target:
                    rewritten_location_path += "?" + new_query_on_target
                # اطمینان از اینکه با / شروع می‌شود اگر خالی نیست
                if not rewritten_location_path.startswith('/') and rewritten_location_path:
                    rewritten_location_path = '/' + rewritten_location_path
                rewritten_location_header_val = rewritten_location_path if rewritten_location_path else "/"

            final_redirect_headers = {'Location': rewritten_location_header_val}
            # سایر هدرهای مهم ریدایرکت را هم منتقل کن
            for h_key, h_val in target_response.headers.items():
                if h_key.lower() in ['set-cookie', 'cache-control', 'expires', 'pragma', 'vary']:
                    final_redirect_headers[h_key] = h_val
            return Response(response=None, status=target_response.status_code, headers=final_redirect_headers)

        # مدیریت خطاهای سرور هدف
        if target_response.status_code >= 400:
            app.logger.warning(f"Target {target_full_url} error: {target_response.status_code}")
            error_content = target_response.content # ممکن است بزرگ باشد
            error_headers_from_target = {
                k:v for k,v in target_response.headers.items() 
                if k.lower() not in ['content-encoding', 'transfer-encoding', 'content-length']
            }
            return Response(response=error_content, status=target_response.status_code, headers=error_headers_from_target)

        content_type = target_response.headers.get('Content-Type', 'application/octet-stream')
        
        excluded_response_headers = [
            'content-encoding', 'transfer-encoding', 'connection', 'keep-alive',
            'x-frame-options', 'strict-transport-security', 'public-key-pins',
            'content-length', 'server', 'x-powered-by', 'date',
            'link',  # <<< مهم: حذف هدر Link از پاسخ
            'x-canonical-url' # <<< مهم: حذف هدر احتمالی دیگر برای URL کنونیکال
        ]
        final_response_headers = {
            key: value for key, value in target_response.headers.items() 
            if key.lower() not in excluded_response_headers
        }
        final_response_headers['Content-Type'] = content_type
        final_response_headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        final_response_headers['Pragma'] = 'no-cache'
        final_response_headers['Expires'] = '0'
        final_response_headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        def generate_response_content_stream():
            # ... (کد طولانی شما برای generate_response_content_stream با تزریق CSS/JS) ...
            # این بخش بسیار طولانی است و برای سادگی اینجا خلاصه شده.
            # اگر این کد Flask اجرا شود، این تابع مسئول تغییر محتوای HTML خواهد بود.
            # در حال حاضر با تنظیمات Nginx، این تابع اجرا نمی‌شود.
            is_html_content_type = 'text/html' in content_type.lower()
            base_tag_injected_flag = False
            css_and_js_injected_flag = False
            
            current_buffer = b''
            charset_match = re.search(r'charset=([\w-]+)', content_type, re.IGNORECASE)
            html_processing_encoding = charset_match.group(1) if charset_match else 'utf-8'

            # محاسبه base href (همانطور که داشتید)
            # ...
            # base_tag_html_to_inject = f'<base href="{escaped_href_for_final_base_tag}">'

            # js_replacements_json = json.dumps(SIMPLE_TEXT_REPLACEMENTS)
            # mutation_observer_script = f"""...""" # اسکریپت JS شما

            try:
                for chunk_data in target_response.iter_content(chunk_size=8192): # chunk_size می‌تواند تنظیم شود
                    if not chunk_data: continue

                    if is_html_content_type:
                        current_buffer += chunk_data
                        # ... (منطق پردازش بافر و تزریق HTML/CSS/JS شما) ...
                        # مثال ساده:
                        # buffer_as_string = current_buffer.decode(html_processing_encoding, errors='replace')
                        # processed_chunk_string = buffer_as_string 
                        # if not css_and_js_injected_flag and '<head>' in processed_chunk_string:
                        #    # تزریق CSS و base tag
                        #    css_and_js_injected_flag = True
                        # if '</body>' in processed_chunk_string:
                        #    # تزریق JS
                        # yield processed_chunk_string.encode(html_processing_encoding, errors='replace')
                        # current_buffer = b''
                        # این بخش باید کامل از کد شما کپی شود اگر می‌خواهید از Flask استفاده کنید.
                        # برای سادگی، اینجا فقط محتوای خام را برمی‌گردانیم:
                        yield chunk_data # در حالت فعلی، برای اینکه کد خلاصه شود.
                                         # اگر این کد Flask فعال شود، باید منطق پردازش HTML شما اینجا باشد.
                    else: # محتوای غیر HTML
                        yield chunk_data
                
                # پردازش باقیمانده بافر (اگر چیزی مانده)
                if current_buffer: 
                    if is_html_content_type:
                        # ... (منطق پردازش باقیمانده بافر HTML شما) ...
                        yield current_buffer # باز هم، برای خلاصه بودن.
                    else:
                        yield current_buffer
            except Exception as stream_err:
                app.logger.error(f"Error during HTML/Stream processing for {target_full_url}: {stream_err}")
            finally:
                target_response.close()

        if request.method == 'HEAD':
            return Response(response=None, status=target_response.status_code, headers=final_response_headers)
        else:
            return Response(stream_with_context(generate_response_content_stream()), status=target_response.status_code, headers=final_response_headers)

    except requests.exceptions.Timeout:
        app.logger.error(f"Timeout ({REQUEST_TIMEOUT}s) fetching {target_full_url}")
        return "Error: Request to target site timed out.", 504
    except requests.exceptions.HTTPError as http_err:
        app.logger.error(f"HTTPError {http_err.response.status_code} from {target_full_url}. Resp: {http_err.response.text[:200]}")
        # ... (کد مدیریت خطا) ...
        return "HTTP Error from target.", 502 # یا وضعیت خطای اصلی
    except requests.exceptions.ConnectionError as conn_err:
        app.logger.error(f"ConnectionError for {target_full_url}: {conn_err}")
        return f"Error: Could not connect to target.", 502
    except requests.exceptions.RequestException as req_err:
        app.logger.error(f"RequestException for {target_full_url}: {req_err}")
        return f"Error fetching content.", 502
    except Exception as general_err:
        app.logger.exception(f"Unexpected Python error proxying {target_full_url}")
        return f"Unexpected server error.", 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 7860)) # پورت استاندارد Hugging Face Spaces
    # debug_mode = os.environ.get('FLASK_ENV') == 'development' or os.environ.get('FLASK_DEBUG', '0') == '1'
    # در Hugging Face معمولا FLASK_DEBUG تنظیم نمی‌شود، مگر اینکه خودتان در Dockerfile یا secrets تنظیم کنید
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    
    print(f"INFO: Starting Flask app on host 0.0.0.0, port {port}, debug: {debug_mode}")
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
