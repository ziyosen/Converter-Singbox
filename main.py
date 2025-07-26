import base64
import json
import re
import urllib.parse
from typing import Dict, Any, List

# Untuk Cloudflare Pages Functions, kita tidak menggunakan FastAPI atau Uvicorn
# Sebagai gantinya, kita akan menggunakan Request dan Response dari werkzeug.wrappers
# Namun, karena ini adalah lingkungan Cloudflare Pages, kita akan membuat fungsi handler
# yang kompatibel dengan format yang diharapkan oleh Cloudflare Pages Functions (FastAPI-like).

# Memuat template Sing-box dari file JSON yang diunggah
# Di Cloudflare Pages Functions, file-file di root proyek dapat diakses.
# Pastikan singbox_template.json berada di root proyek Anda.
try:
    with open("singbox_template.json", "r") as f:
        SINGBOX_TEMPLATE = json.load(f)
except FileNotFoundError:
    # Jika file tidak ditemukan, inisialisasi dengan struktur dasar atau log error
    print("Error: singbox_template.json not found. Using empty template.")
    SINGBOX_TEMPLATE = {
        "log": {"disabled": True},
        "dns": {"servers": [], "rules": [], "strategy": "ipv4_only"},
        "inbounds": [],
        "outbounds": [
            {"type": "selector", "tag": "🌐 Internet", "outbounds": ["direct-out"], "default": "direct-out"},
            {"type": "direct", "tag": "direct-out"},
            {"type": "block", "tag": "block"}
        ],
        "route": {"rules": [], "final": "🌐 Internet"}
    }
except json.JSONDecodeError as e:
    print(f"Error: Invalid JSON format in singbox_template.json: {e}")
    SINGBOX_TEMPLATE = {
        "log": {"disabled": True},
        "dns": {"servers": [], "rules": [], "strategy": "ipv4_only"},
        "inbounds": [],
        "outbounds": [
            {"type": "selector", "tag": "🌐 Internet", "outbounds": ["direct-out"], "default": "direct-out"},
            {"type": "direct", "tag": "direct-out"},
            {"type": "block", "tag": "block"}
        ],
        "route": {"rules": [], "final": "🌐 Internet"}
    }
except Exception as e:
    print(f"An unexpected error occurred while loading singbox_template.json: {e}")
    SINGBOX_TEMPLATE = {
        "log": {"disabled": True},
        "dns": {"servers": [], "rules": [], "strategy": "ipv4_only"},
        "inbounds": [],
        "outbounds": [
            {"type": "selector", "tag": "🌐 Internet", "outbounds": ["direct-out"], "default": "direct-out"},
            {"type": "direct", "tag": "direct-out"},
            {"type": "block", "tag": "block"}
        ],
        "route": {"rules": [], "final": "🌐 Internet"}
    }


# Fungsi handler utama untuk Cloudflare Pages Function
# Nama fungsi harus 'onRequestPost' atau 'onRequest' untuk GET/POST
async def onRequestPost(context):
    try:
        # Mengambil body request sebagai JSON
        request_body = await context.request.json()
        input_text = request_body.get("input_text", "")

        result = {}
        error = None

        if not input_text:
            error = "Please enter at least one configuration."
            return Response(json.dumps({"error": error}), headers={"Content-Type": "application/json"}, status=400)

        # Buat salinan template untuk setiap konversi
        template_copy = json.loads(json.dumps(SINGBOX_TEMPLATE))
        
        # Pisahkan input berdasarkan baris untuk menangani beberapa konfigurasi
        config_lines = [line.strip() for line in input_text.split('\n') if line.strip()]

        for config in config_lines:
            try:
                if config.startswith("vmess://"):
                    add_vmess_to_template(template_copy, config)
                elif config.startswith("vless://"):
                    add_vless_to_template(template_copy, config)
                elif config.startswith("trojan://"):
                    add_trojan_to_template(template_copy, config)
                elif config.startswith("ss://"):
                    add_shadowsocks_to_template(template_copy, config)
                elif config.startswith("v2ray://"): # V2Ray biasanya VMess, tapi jika ada format lain, bisa ditambahkan
                    add_vmess_to_template(template_copy, config.replace("v2ray://", "vmess://")) # Asumsi V2Ray adalah VMess
                else:
                    print(f"Skipping unsupported config format: {config}")
                    continue
            except Exception as e:
                print(f"Error processing config '{config}': {str(e)}")
                # Lanjutkan memproses konfigurasi lain meskipun ada error pada satu baris
                continue
        
        result = json.dumps(template_copy, indent=2)
        return Response(json.dumps({"result": json.loads(result)}), headers={"Content-Type": "application/json"})

    except json.JSONDecodeError:
        error = "Invalid JSON input in request body."
        return Response(json.dumps({"error": error}), headers={"Content-Type": "application/json"}, status=400)
    except Exception as e:
        error = f"Conversion error: {str(e)}"
        print(f"Server error: {e}") # Log error untuk debugging
        return Response(json.dumps({"error": error}), headers={"Content-Type": "application/json"}, status=500)

# --- Fungsi Pembantu Konversi ---

def add_outbound_to_selectors(template: Dict[str, Any], tag: str) -> None:
    """Tambahkan tag outbound ke semua selector yang relevan."""
    for ob in template.get("outbounds", []):
        if ob.get("type") in ["selector", "urltest"] and "outbounds" in ob and isinstance(ob["outbounds"], list):
            if tag not in ob["outbounds"]:
                ob["outbounds"].append(tag)

def get_vmess_transport_config(vmess_config: dict) -> dict:
    """Hasilkan konfigurasi transport untuk VMess."""
    network = vmess_config.get("net", "tcp")
    
    if network == "ws":
        return {
            "type": "ws",
            "path": vmess_config.get("path", "/"),
            "headers": {
                "Host": vmess_config.get("host", "")
            }
        }
    elif network == "grpc":
        return {
            "type": "grpc",
            "service_name": vmess_config.get("path", "")
        }
    elif network == "http":
        return {
            "type": "http",
            "host": [vmess_config.get("host")] if vmess_config.get("host") else [],
            "path": vmess_config.get("path", "/")
        }
    elif network == "tcp":
        if vmess_config.get("type") == "http": # Ini adalah 'type' di dalam config JSON, bukan 'net'
            return {
                "type": "http",
                "host": [vmess_config.get("host")] if vmess_config.get("host") else [],
                "path": vmess_config.get("path", "/")
            }
        return {"type": "tcp"}
    else:
        return {"type": "tcp"}

def get_vless_transport_config(type_param: str, host: str, path: str, params: dict) -> dict:
    """Hasilkan konfigurasi transport untuk VLess."""
    if type_param == "ws":
        return {
            "type": "ws",
            "path": path,
            "headers": {
                "Host": host
            }
        }
    elif type_param == "grpc":
        return {
            "type": "grpc",
            "service_name": path
        }
    elif type_param == "http":
        return {
            "type": "http",
            "host": [host] if host else [],
            "path": path or "/"
        }
    else:  # tcp atau default
        return {"type": "tcp"}

def get_trojan_transport_config(type_param: str, host: str, path: str, params: dict) -> dict:
    """Hasilkan konfigurasi transport untuk Trojan."""
    if type_param == "ws":
        return {
            "type": "ws",
            "path": path,
            "headers": {
                "Host": host
            }
        }
    elif type_param == "grpc":
        return {
            "type": "grpc",
            "service_name": path
        }
    elif type_param == "http":
        return {
            "type": "http",
            "host": [host] if host else [],
            "path": path or "/"
        }
    else:  # tcp atau default
        return {"type": "tcp"}

def create_ss_v2ray_outbound(server, port, method, password, plugin_opts, tag, params):
    """Buat outbound Shadowsocks dengan v2ray-plugin."""
    opts_dict = {}
    for opt in plugin_opts.split(';'):
        if not opt:
            continue
        if '=' in opt:
            key, value = opt.split('=', 1)
            opts_dict[key] = value
        else:
            opts_dict[opt] = True
    
    # Periksa apakah TLS diaktifkan
    tls_enabled = 'tls' in opts_dict
    
    # Periksa apakah WebSocket digunakan
    ws_mode = opts_dict.get('mode') == 'websocket'
    
    if ws_mode:
        ws_path = opts_dict.get('path', '/')
        ws_host = opts_dict.get('host', '')
        
        return {
            "type": "shadowsocks",
            "tag": tag,
            "server": server,
            "server_port": int(port),
            "method": method,
            "password": password,
            "plugin": "v2ray-plugin",
            "plugin_opts": plugin_opts # Pertahankan plugin_opts asli
        }
    else:
        return {
            "type": "shadowsocks",
            "tag": tag,
            "server": server,
            "server_port": int(port),
            "method": method,
            "password": password,
            "plugin": "v2ray-plugin",
            "plugin_opts": plugin_opts # Pertahankan plugin_opts asli
        }

def add_vmess_to_template(template: Dict[str, Any], vmess_url: str) -> None:
    """Tambahkan konfigurasi VMess ke template."""
    try:
        base64_content = vmess_url.replace("vmess://", "").replace("v2ray://", "")
        decoded_content = base64.b64decode(base64_content).decode('utf-8')
        vmess_config = json.loads(decoded_content)
        
        original_tag = vmess_config.get("ps", "vmess-outbound")
        tag = f"VMess - {original_tag}"
        
        outbound = {
            "type": "vmess",
            "tag": tag,
            "server": vmess_config.get("add"),
            "server_port": int(vmess_config.get("port")),
            "uuid": vmess_config.get("id"),
            "security": vmess_config.get("scy", "auto"),
            "alter_id": int(vmess_config.get("aid", 0)),
            "tls": {
                "enabled": vmess_config.get("tls") == "tls",
                "server_name": vmess_config.get("sni") or vmess_config.get("host", ""),
                "insecure": vmess_config.get("verify_cert") is False,
            },
            "transport": get_vmess_transport_config(vmess_config),
        }
        
        template["outbounds"].append(outbound)
        add_outbound_to_selectors(template, tag)
        
    except Exception as e:
        raise ValueError(f"Invalid VMess configuration format: {str(e)}")

def add_vless_to_template(template: Dict[str, Any], vless_url: str) -> None:
    """Tambahkan konfigurasi VLess ke template."""
    try:
        url_match = re.match(r'^vless://([^@]+)@([^:]+):(\d+)\?(.+?)(?:#(.+))?$', vless_url)
        
        if not url_match:
            raise ValueError("Invalid VLESS URL format")
        
        uuid, server, port, params_string, fragment = url_match.groups()
        params = dict(urllib.parse.parse_qsl(params_string))
        
        type_param = params.get("type", "tcp")
        security = params.get("security", "none")
        sni = params.get("sni", "")
        fp = params.get("fp", "")
        alpn = params.get("alpn", "")
        path = params.get("path", "")
        host = params.get("host", "")
        
        original_tag = urllib.parse.unquote(fragment) if fragment else params.get("name", f"vless-{server}-{port}")
        tag = f"VLess - {original_tag}"
        
        outbound = {
            "type": "vless",
            "tag": tag,
            "server": server,
            "server_port": int(port),
            "uuid": uuid,
            "flow": params.get("flow", ""),
            "tls": {
                "enabled": security in ["tls", "xtls"],
                "server_name": sni,
                "utls": {
                    "enabled": bool(fp),
                    "fingerprint": fp,
                },
                "alpn": alpn.split(",") if alpn else [],
            },
            "transport": get_vless_transport_config(type_param, host, path, params),
        }
        
        template["outbounds"].append(outbound)
        add_outbound_to_selectors(template, tag)
        
    except Exception as e:
        raise ValueError(f"Invalid VLESS configuration format: {str(e)}")

def add_trojan_to_template(template: Dict[str, Any], trojan_url: str) -> None:
    """Tambahkan konfigurasi Trojan ke template."""
    try:
        url_match = re.match(r'^trojan://([^@]+)@([^:]+):(\d+)(?:\?(.+?))?(?:#(.+))?$', trojan_url)
        
        if not url_match:
            raise ValueError("Invalid Trojan URL format")
        
        password, server, port, params_string, fragment = url_match.groups()
        params = dict(urllib.parse.parse_qsl(params_string or ""))
        
        sni = params.get("sni", "")
        alpn = params.get("alpn", "")
        type_param = params.get("type", "tcp")
        host = params.get("host", "")
        path = params.get("path", "")
        
        original_tag = urllib.parse.unquote(fragment) if fragment else params.get("name", f"trojan-{server}-{port}")
        tag = f"Trojan - {original_tag}"
        
        outbound = {
            "type": "trojan",
            "tag": tag,
            "server": server,
            "server_port": int(port),
            "password": password,
            "tls": {
                "enabled": True,
                "server_name": sni,
                "alpn": alpn.split(",") if alpn else [],
            }
        }
        
        if type_param != "tcp":
            outbound["transport"] = get_trojan_transport_config(type_param, host, path, params)
        
        template["outbounds"].append(outbound)
        add_outbound_to_selectors(template, tag)
        
    except Exception as e:
        raise ValueError(f"Invalid Trojan configuration format: {str(e)}")

def add_shadowsocks_to_template(template: Dict[str, Any], ss_url: str) -> None:
    """Tambahkan konfigurasi Shadowsocks ke template."""
    try:
        match = re.match(r'^ss://([^@]+)@([^:]+):(\d+)(?:\?(.+?))?(?:#(.+))?$', ss_url)
        if not match:
            raise ValueError("Invalid Shadowsocks URL format")

        base64_part, server, port, params_str, fragment = match.groups()
        base64_part = urllib.parse.unquote(base64_part)
        try:
            decoded = base64.b64decode(base64_part).decode('utf-8')
            method, password = decoded.split(':', 1)
        except Exception:
            raise ValueError("Invalid base64 encoding in Shadowsocks URL")

        params = dict(urllib.parse.parse_qsl(params_str or ""))
        method = params.get('encryption', method)

        original_tag = urllib.parse.unquote(fragment) if fragment else f"ss-{server}-{port}"
        original_tag = re.sub(r"[^\x00-\x7F]+", "", original_tag).strip()
        tag = f"Shadowsocks - {original_tag}"

        plugin_raw = urllib.parse.unquote(params.get('plugin', ''))
        plugin = ''
        plugin_opts = ''
        if plugin_raw:
            if ';' in plugin_raw:
                plugin, plugin_opts = plugin_raw.split(';', 1)
            else:
                plugin = plugin_raw

        if plugin == 'v2ray-plugin':
            outbound = create_ss_v2ray_outbound(server, port, method, password, plugin_opts, tag, params)
        else:
            outbound = {
                'type': 'shadowsocks',
                'tag': tag,
                'server': server,
                'server_port': int(port),
                'method': method,
                'password': password
            }
            if plugin:
                outbound['plugin'] = plugin
                outbound['plugin_opts'] = plugin_opts

        template['outbounds'].append(outbound)
        add_outbound_to_selectors(template, tag)

    except Exception as e:
        raise ValueError(f"Invalid Shadowsocks configuration format: {e}")

# Kelas Response sederhana untuk Pages Functions
class Response:
    def __init__(self, body, headers=None, status=200):
        self.body = body
        self.headers = headers or {}
        self.status = status

    def __call__(self):
        return {
            "body": self.body,
            "headers": self.headers,
            "status": self.status
        }
