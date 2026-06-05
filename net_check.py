#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSPU Диагностический инструмент v4.6 — Python-версия
Анализ работы ТСПУ в российских сетях.
"""

from __future__ import annotations

import http.server
import os
import platform
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

VERSION = "4.6"
DEFAULT_SERVER_IP = "178.154.212.182"
DEFAULT_REALITY_SNI = "www.microsoft.com"
DEFAULT_REALITY_PORT = 443
BLOCKED_TEST_IP = "173.194.222.113"
SNI_TEST_IP = "77.88.55.242"

# Типичные REALITY dest для быстрого выбора
REALITY_SNI_PRESETS = [
    "www.microsoft.com",
    "www.cloudflare.com",
    "www.google.com",
    "www.apple.com",
    "www.samsung.com",
    "dl.google.com",
    "update.googleapis.com",
]

# ANSI-цвета
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
CYAN = "\033[0;36m"
NC = "\033[0m"


def enable_ansi_windows() -> None:
    if sys.platform == "win32":
        os.system("")


SCRIPT_DIR = Path(__file__).resolve().parent


def config_file() -> Path:
    return SCRIPT_DIR / "server.conf"


@dataclass
class TlsProbeResult:
    status: str  # ok | server_hello | alert | reset | timeout | tcp_fail | error
    detail: str
    bytes_received: int = 0
    record_type: int | None = None
    alert_name: str | None = None

    @property
    def path_reachable(self) -> bool:
        """До сервера дошли: ответ TLS есть (в т.ч. REALITY отклонил чужой Client Hello)."""
        if self.status in ("ok", "server_hello"):
            return True
        if self.status == "alert" and self.alert_name == "handshake_failure":
            return True
        return False


class TspuChecker:
    def __init__(self) -> None:
        enable_ansi_windows()
        self.server_ip = DEFAULT_SERVER_IP
        self.reality_sni = DEFAULT_REALITY_SNI
        self.reality_port = DEFAULT_REALITY_PORT
        config_file().parent.mkdir(parents=True, exist_ok=True)
        self.load_config()

    # ------------------------------------------------------------------ config

    def load_config(self) -> None:
        path = config_file()
        if not path.is_file():
            old_path = Path.home() / ".config" / "tspu_checker" / "server.conf"
            if old_path.is_file():
                path.write_text(old_path.read_text(encoding="utf-8"), encoding="utf-8")
                print(f"{CYAN}↪ Конфиг перенесён из {old_path}{NC}")

        if path.is_file():
            text = path.read_text(encoding="utf-8")
            ip_match = re.search(r'SERVER_IP\s*=\s*"([^"]+)"', text)
            if not ip_match:
                ip_match = re.search(r"^([\d.]+)\s*$", text.strip(), re.MULTILINE)
            sni_match = re.search(r'REALITY_SNI\s*=\s*"([^"]+)"', text)
            port_match = re.search(r'REALITY_PORT\s*=\s*"?(\d+)"?', text)
            if ip_match:
                self.server_ip = ip_match.group(1)
            if sni_match:
                self.reality_sni = sni_match.group(1)
            if port_match:
                self.reality_port = int(port_match.group(1))
            print(f"{GREEN}✓ Конфиг: сервер {self.server_ip}, REALITY SNI {self.reality_sni}:{self.reality_port}{NC}")
        else:
            print(
                f"{YELLOW}⚠ По умолчанию: {DEFAULT_SERVER_IP}, "
                f"SNI {DEFAULT_REALITY_SNI}:{DEFAULT_REALITY_PORT}{NC}"
            )
        print()

    def save_config(self) -> None:
        config_file().write_text(
            f'SERVER_IP="{self.server_ip}"\n'
            f'REALITY_SNI="{self.reality_sni}"\n'
            f'REALITY_PORT="{self.reality_port}"\n',
            encoding="utf-8",
        )

    def save_server_ip(self, ip: str) -> None:
        self.server_ip = ip
        self.save_config()
        print(f"{GREEN}✓ IP сохранён: {ip}{NC}")

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def clear_screen() -> None:
        os.system("cls" if sys.platform == "win32" else "clear")

    @staticmethod
    def pause() -> None:
        input(f"\n{YELLOW}Нажмите Enter для продолжения...{NC}")

    def print_header(self) -> None:
        print(f"{BLUE}========================================{NC}")
        print(f"{BLUE}     ТСПУ Диагностический инструмент    {NC}")
        print(f"{BLUE}              v{VERSION}                      {NC}")
        print(f"{BLUE}========================================{NC}\n")
        print(f"{CYAN}🎯 VPN-сервер: {GREEN}{self.server_ip}:{self.reality_port}{NC}")
        print(f"{CYAN}🎭 REALITY SNI (dest): {GREEN}{self.reality_sni}{NC}\n")

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    @staticmethod
    def is_valid_port(port: int) -> bool:
        return 1 <= port <= 65535

    @staticmethod
    def is_valid_sni(sni: str) -> bool:
        if not sni or " " in sni or len(sni) > 253:
            return False
        return bool(re.match(
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
            r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
            sni,
        ))

    def vpn_config_valid(self) -> bool:
        return (
            self.is_valid_ip(self.server_ip)
            and self.is_valid_port(self.reality_port)
            and self.is_valid_sni(self.reality_sni)
        )

    def get_vpn_targets(self) -> tuple[str, int, str] | None:
        """Вернуть host/port/sni из конфига или запросить, если параметры невалидны."""
        if self.vpn_config_valid():
            return self.server_ip, self.reality_port, self.reality_sni

        print(f"{YELLOW}⚠ Параметры VPN не заданы или некорректны.{NC}")
        print(f"  IP:   {self.server_ip!r} {'✓' if self.is_valid_ip(self.server_ip) else '✗'}")
        print(f"  Порт: {self.reality_port} {'✓' if self.is_valid_port(self.reality_port) else '✗'}")
        print(f"  SNI:  {self.reality_sni!r} {'✓' if self.is_valid_sni(self.reality_sni) else '✗'}")
        print(f"\n{CYAN}Настройте их в п. 16 или введите сейчас.{NC}\n")

        host = input(f"IP/хост [{self.server_ip}]: ").strip() or self.server_ip
        if not self.is_valid_ip(host):
            print(f"{RED}❌ Неверный IP{NC}")
            return None

        port_str = input(f"Порт [{self.reality_port}]: ").strip()
        try:
            port = int(port_str) if port_str else self.reality_port
        except ValueError:
            print(f"{RED}❌ Неверный порт{NC}")
            return None
        if not self.is_valid_port(port):
            print(f"{RED}❌ Порт должен быть 1–65535{NC}")
            return None

        sni = input(f"SNI [{self.reality_sni}]: ").strip() or self.reality_sni
        if not self.is_valid_sni(sni):
            print(f"{RED}❌ Неверный SNI (домен){NC}")
            return None

        self.server_ip, self.reality_port, self.reality_sni = host, port, sni
        self.save_config()
        return host, port, sni

    @staticmethod
    def check_port_tcp(host: str, port: int, timeout: float = 3.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    @staticmethod
    def ping_host(host: str, count: int = 2, timeout_sec: int = 2) -> bool:
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", str(count), "-w", str(timeout_sec * 1000), host]
        elif system == "darwin":
            cmd = ["ping", "-c", str(count), "-W", str(timeout_sec * 1000), host]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(timeout_sec), host]

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout_sec * count + 5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    @staticmethod
    def http_status(url: str, timeout: float = 5.0) -> int | None:
        req = urllib.request.Request(url, headers={"User-Agent": "tspu-checker/4.6"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
        except (urllib.error.URLError, OSError, TimeoutError):
            return None

    @staticmethod
    def _encode_dns_name(domain: str) -> bytes:
        result = b""
        for part in domain.strip(".").split("."):
            result += bytes([len(part)]) + part.encode("ascii")
        return result + b"\x00"

    @classmethod
    def dns_query_a(cls, domain: str, server: str | None = None, timeout: float = 3.0) -> list[str]:
        """Запрос A-записей через dig или сырой UDP DNS."""
        dig = shutil.which("dig")
        if dig:
            cmd = [dig, domain, "+short"]
            if server:
                cmd = [dig, f"@{server}", domain, "+short"]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().splitlines()
                    return [ln.strip() for ln in lines if re.match(r"^\d+\.\d+\.\d+\.\d+$", ln.strip())]
            except (subprocess.TimeoutExpired, OSError):
                pass

        if not server:
            try:
                infos = socket.getaddrinfo(domain, None, socket.AF_INET)
                return list({info[4][0] for info in infos})
            except socket.gaierror:
                return []

        tid = random.randint(0, 65535)
        header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        question = cls._encode_dns_name(domain) + struct.pack("!HH", 1, 1)
        packet = header + question

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(4096)
        except (socket.timeout, OSError):
            return []
        finally:
            sock.close()

        if len(data) < 12:
            return []
        _, _, ancount, _, _, _ = struct.unpack("!HHHHHH", data[:12])
        offset = 12
        while offset < len(data) and data[offset] != 0:
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
                break
            offset += data[offset] + 1
        else:
            offset += 1
        offset += 4  # QTYPE + QCLASS

        ips: list[str] = []
        for _ in range(ancount):
            if offset >= len(data):
                break
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += data[offset] + 1
                offset += 1
            if offset + 10 > len(data):
                break
            rtype, _, _, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            rdata = data[offset : offset + rdlength]
            offset += rdlength
            if rtype == 1 and rdlength == 4:
                ips.append(".".join(str(b) for b in rdata))
        return ips

    @staticmethod
    def tls_handshake(host: str, port: int = 443, sni: str | None = None, timeout: float = 5.0) -> str:
        return TspuChecker.tls_probe_openssl(host, port, sni, timeout).status

    @staticmethod
    def _is_connection_reset(exc: BaseException) -> bool:
        if isinstance(exc, ConnectionResetError):
            return True
        if isinstance(exc, OSError):
            if "reset" in str(exc).lower():
                return True
            if getattr(exc, "winerror", None) == 10054:
                return True
            errno = getattr(exc, "errno", None)
            if errno in (104, 54, 10054):
                return True
        return False

    @staticmethod
    def _classify_ssl_error(exc: ssl.SSLError) -> TlsProbeResult:
        reason = (getattr(exc, "reason", None) or str(exc)).upper()
        alert_names = {
            "HANDSHAKE_FAILURE": "handshake_failure",
            "INTERNAL_ERROR": "internal_error",
            "UNRECOGNIZED_NAME": "unrecognized_name",
            "CERTIFICATE_UNKNOWN": "certificate_unknown",
            "BAD_CERTIFICATE": "bad_certificate",
            "ACCESS_DENIED": "access_denied",
            "PROTOCOL_VERSION": "protocol_version",
            "INSUFFICIENT_SECURITY": "insufficient_security",
        }
        for token, name in alert_names.items():
            if token in reason:
                if name == "handshake_failure":
                    return TlsProbeResult(
                        "alert",
                        "Сервер ответил handshake_failure — типично для REALITY "
                        "(отклонён не-VLESS клиент, путь до VPS открыт)",
                        alert_name=name,
                    )
                return TlsProbeResult(
                    "alert",
                    f"Сервер ответил TLS Alert: {name}",
                    alert_name=name,
                )
        return TlsProbeResult("error", f"SSL: {exc}")

    @staticmethod
    def tls_probe_openssl(
        host: str, port: int = 443, sni: str | None = None, timeout: float = 5.0
    ) -> TlsProbeResult:
        """Полный TLS через OpenSSL (отпечаток Python, не VPN-клиента)."""
        sni = sni or host
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    with ctx.wrap_socket(raw, server_hostname=sni) as ssock:
                        version = ssock.version() or "unknown"
                        cipher = ssock.cipher()
                        cipher_name = cipher[0] if cipher else "unknown"
                        return TlsProbeResult(
                            "ok",
                            f"TLS {version}, cipher {cipher_name}",
                        )
                except ssl.SSLError as e:
                    return TspuChecker._classify_ssl_error(e)
        except ConnectionResetError:
            return TlsProbeResult("reset", "Connection reset после Client Hello (DPI/SNI)")
        except OSError as e:
            if TspuChecker._is_connection_reset(e):
                return TlsProbeResult("reset", "Connection reset (DPI/SNI)")
            if isinstance(e, TimeoutError) or getattr(e, "errno", None) in (110, 10060):
                return TlsProbeResult("timeout", "Таймаут TCP/TLS")
            return TlsProbeResult("tcp_fail", str(e))

    @staticmethod
    def _alpn_extension() -> bytes:
        protos = b"".join(bytes([len(p)]) + p for p in (b"h2", b"http/1.1"))
        inner = struct.pack("!H", len(protos)) + protos
        return b"\x00\x10" + struct.pack("!H", len(inner)) + inner

    @staticmethod
    def build_client_hello(sni: str, profile: str = "chrome") -> bytes:
        """Собрать TLS 1.3 ClientHello (Chrome-подобный) с указанным SNI."""
        host = sni.encode("ascii")
        sni_name = b"\x00" + struct.pack("!H", len(host)) + host
        sni_list = struct.pack("!H", len(sni_name)) + sni_name
        sni_ext = b"\x00\x00" + struct.pack("!H", len(sni_list)) + sni_list

        if profile == "minimal":
            suites = [0x1301, 0x1302, 0xC02F, 0xC02B]
        else:
            suites = [
                0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
                0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
            ]
        cs_body = b"".join(struct.pack("!H", s) for s in suites)
        cipher_suites = struct.pack("!H", len(cs_body)) + cs_body

        groups = b"\x00\x1d\x00\x17\x00\x18\x00\x19"
        groups_body = struct.pack("!H", len(groups)) + groups
        groups_ext = b"\x00\x0a" + struct.pack("!H", len(groups_body)) + groups_body

        ecf = b"\x01\x00"
        ecf_ext = b"\x00\x0b" + struct.pack("!H", len(ecf)) + ecf

        sig_algs = bytes.fromhex(
            "040304080502060505010506040101050103081501081005080605010806060201"
        )
        sig_body = struct.pack("!H", len(sig_algs)) + sig_algs
        sig_ext = b"\x00\x0d" + struct.pack("!H", len(sig_body)) + sig_body

        vers = b"\x02\x03\x04"
        vers_ext = b"\x00\x2b" + struct.pack("!H", len(vers)) + vers

        key_entry = b"\x00\x1d" + struct.pack("!H", 32) + os.urandom(32)
        ks_inner = struct.pack("!H", len(key_entry)) + key_entry
        ks_ext = b"\x00\x33" + struct.pack("!H", len(ks_inner)) + ks_inner

        psk_modes = b"\x01\x01"
        psk_ext = b"\x00\x2d" + struct.pack("!H", len(psk_modes)) + psk_modes

        extensions = sni_ext + groups_ext + ecf_ext + sig_ext + TspuChecker._alpn_extension() + vers_ext + ks_ext + psk_ext
        extensions_block = struct.pack("!H", len(extensions)) + extensions

        legacy_version = b"\x03\x03"
        random_bytes = os.urandom(32)
        session_id = b"\x00"
        compression = b"\x01\x00"
        client_hello_body = legacy_version + random_bytes + session_id + cipher_suites + compression + extensions_block
        handshake_msg = b"\x01" + struct.pack("!I", len(client_hello_body))[1:] + client_hello_body
        return b"\x16\x03\x01" + struct.pack("!H", len(handshake_msg)) + handshake_msg

    @staticmethod
    def _tls_alert_name(code: int) -> str:
        names = {
            40: "handshake_failure",
            41: "no_certificate",
            42: "bad_certificate",
            43: "unsupported_certificate",
            44: "certificate_revoked",
            45: "certificate_expired",
            46: "certificate_unknown",
            47: "illegal_parameter",
            48: "unknown_ca",
            49: "access_denied",
            50: "decode_error",
            51: "decrypt_error",
            70: "protocol_version",
            71: "insufficient_security",
            80: "internal_error",
            112: "unrecognized_name",
        }
        return names.get(code, f"alert_{code}")

    @staticmethod
    def _analyze_tls_response(data: bytes) -> TlsProbeResult:
        if not data:
            return TlsProbeResult("timeout", "Пустой ответ после Client Hello")
        record_type = data[0]
        if record_type == 0x16:
            if b"\x02" in data[:200]:
                return TlsProbeResult(
                    "server_hello",
                    "Получен Server Hello — TLS не заблокирован на этом этапе",
                    len(data),
                    record_type,
                )
            return TlsProbeResult(
                "server_hello",
                "Получен TLS Handshake (возможно Server Hello / Encrypted Extensions)",
                len(data),
                record_type,
            )
        if record_type == 0x15:
            alert_name = None
            detail = "TLS Alert от сервера"
            if len(data) >= 7:
                alert_name = TspuChecker._tls_alert_name(data[6])
                detail = f"TLS Alert: {alert_name}"
                if alert_name == "handshake_failure":
                    detail += " — типично для REALITY (путь до VPS открыт)"
            return TlsProbeResult(
                "alert",
                detail,
                len(data),
                record_type,
                alert_name=alert_name,
            )
        if record_type == 0x17:
            return TlsProbeResult(
                "ok",
                "Получены зашифрованные данные (TLS 1.3 продолжение)",
                len(data),
                record_type,
            )
        return TlsProbeResult(
            "error",
            f"Неожиданный тип записи TLS: 0x{record_type:02x}",
            len(data),
            record_type,
        )

    @staticmethod
    def probe_raw_client_hello(
        host: str,
        port: int,
        sni: str,
        profile: str = "chrome",
        timeout: float = 5.0,
    ) -> TlsProbeResult:
        """Отправить сырой ClientHello и прочитать первый ответ."""
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                hello = TspuChecker.build_client_hello(sni, profile)
                sock.sendall(hello)
                try:
                    data = sock.recv(8192)
                except ConnectionResetError:
                    return TlsProbeResult(
                        "reset",
                        "RST после Client Hello — вероятна SNI/DPI-блокировка ТСПУ",
                    )
                return TspuChecker._analyze_tls_response(data)
        except ConnectionResetError:
            return TlsProbeResult("reset", "RST при подключении")
        except OSError as e:
            if TspuChecker._is_connection_reset(e):
                return TlsProbeResult("reset", "RST при отправке Client Hello")
            if isinstance(e, TimeoutError) or getattr(e, "errno", None) in (110, 10060):
                return TlsProbeResult("timeout", "Таймаут")
            return TlsProbeResult("tcp_fail", str(e))

    @staticmethod
    def _print_probe(label: str, result: TlsProbeResult) -> None:
        if result.path_reachable and result.status == "alert":
            color = GREEN
            tag = f"OK (alert:{result.alert_name})"
        else:
            colors = {
                "ok": GREEN,
                "server_hello": GREEN,
                "reset": RED,
                "timeout": YELLOW,
                "alert": YELLOW,
                "tcp_fail": RED,
                "error": RED,
            }
            color = colors.get(result.status, YELLOW)
            tag = result.status.upper()
        extra = f" ({result.bytes_received} байт)" if result.bytes_received else ""
        print(f"  {label}: {color}{tag}{NC} — {result.detail}{extra}")

    @staticmethod
    def get_local_ip() -> str | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except OSError:
            pass
        if sys.platform != "win32":
            try:
                result = subprocess.run(
                    ["ip", "-4", "addr", "show"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                for line in result.stdout.splitlines():
                    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                    if m and not m.group(1).startswith("127."):
                        return m.group(1)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
        return None

    @staticmethod
    def get_external_ip() -> str | None:
        for url in ("https://ifconfig.me/ip", "https://api.ipify.org", "https://ifconfig.me"):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "tspu-checker/4.6"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    text = resp.read().decode("utf-8", errors="replace").strip()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", text):
                        return text
            except (urllib.error.URLError, OSError, TimeoutError):
                continue
        return None

    @staticmethod
    def https_remote_ip(host: str, timeout: float = 5.0) -> str | None:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, 443), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                    return ssock.getpeername()[0]
        except (ssl.SSLError, OSError, TimeoutError):
            return None

    # ------------------------------------------------------------------ menu actions

    def configure_server_ip(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[0] 🔧 Настройка IP адреса сервера{NC}\n")
        print(f"{CYAN}Текущий IP: {GREEN}{self.server_ip}{NC}\n")
        new_ip = input("Введите новый IP (или оставьте пустым): ").strip()
        if new_ip:
            if self.is_valid_ip(new_ip):
                self.save_server_ip(new_ip)
                self.server_ip = new_ip
                print(f"\n{GREEN}✅ IP изменён на {self.server_ip}{NC}")
            else:
                print(f"\n{RED}❌ Неверный формат IP{NC}")
        self.pause()

    def detect_tspu_mode(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[1] 🧪 Определение режима работы ТСПУ...{NC}\n")
        print(f"{CYAN}🔬 Тестовый IP (Google): {BLOCKED_TEST_IP}{NC}\n")

        print("  ICMP (ping) Google: ", end="", flush=True)
        icmp_ok = self.ping_host(BLOCKED_TEST_IP)
        print(f"{GREEN}ДОСТУПЕН ✓{NC}" if icmp_ok else f"{RED}НЕ ДОСТУПЕН ✗{NC}")

        print("  TCP Google:443: ", end="", flush=True)
        tcp_ok = self.check_port_tcp(BLOCKED_TEST_IP, 443)
        print(f"{GREEN}ДОСТУПЕН ✓{NC}" if tcp_ok else f"{RED}НЕ ДОСТУПЕН ✗{NC}")

        print(f"\n{CYAN}📊 Режим работы:{NC}\n")
        if icmp_ok and not tcp_ok:
            print(f"  {RED}⚠️ РЕЖИМ БЕЛЫХ СПИСКОВ (allowlist){NC}")
            print("     • ICMP работает, TCP блокируется на L3")
        elif not icmp_ok and not tcp_ok:
            print(f"  {YELLOW}⚠️ РЕЖИМ ЧЁРНЫХ СПИСКОВ или ПОЛНАЯ БЛОКИРОВКА{NC}")
        elif icmp_ok and tcp_ok:
            print(f"  {GREEN}✅ БЛОКИРОВКИ НЕТ (нормальный режим){NC}")
        self.pause()

    def check_tspu_active(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[2] 📡 Проверка активности ТСПУ (доступ к сайтам)...{NC}\n")
        print(f"{CYAN}📡 Проверка через HTTP:{NC}\n")

        sites = [
            ("ya.ru", "Яндекс"),
            ("google.com", "Google"),
            ("youtube.com", "YouTube"),
            ("github.com", "GitHub"),
            ("telegram.org", "Telegram"),
            ("rutracker.org", "rutracker"),
            ("linkedin.com", "linkedin"),
            ("x.com", "twitter"),
            ("instagram.com", "instagram"),
        ]
        for url, name in sites:
            print(f"  {name} ({url}): ", end="", flush=True)
            code = self.http_status(f"https://{url}")
            if code and str(code)[0] in "23":
                print(f"{GREEN}ДОСТУПЕН (HTTP {code}) ✓{NC}")
            else:
                print(f"{RED}НЕ ДОСТУПЕН ✗{NC}")

        print(f"\n{CYAN}🔌 Проверка сервера {self.server_ip}:{NC}\n")
        for port in (22, 80, 443):
            print(f"  Порт {port}: ", end="", flush=True)
            if self.check_port_tcp(self.server_ip, port):
                print(f"{GREEN}ОТКРЫТ ✓{NC}")
            else:
                print(f"{YELLOW}ЗАКРЫТ/ФИЛЬТР{NC}")
        self.pause()

    def check_ports(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[3] 🔍 Проверка доступности портов (TCP)...{NC}\n")
        print(f"{CYAN}🎯 Цель: {self.server_ip}{NC}\n")
        for port in (22, 80, 443, 8080, 8443, 2443, 4443, 54982, 39561, 56676):
            print(f"  Порт {port}: ", end="", flush=True)
            if self.check_port_tcp(self.server_ip, port):
                print(f"{GREEN}ОТКРЫТ ✓{NC}")
            else:
                print(f"{YELLOW}ЗАКРЫТ/НЕТ ОТВЕТА{NC}")
            time.sleep(0.2)
        self.pause()

    def test_sni_filtering(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[4] 🎭 Проверка SNI-фильтрации на L7...{NC}\n")
        print(f"{CYAN}🎯 Тестовый IP (Яндекс): {SNI_TEST_IP}{NC}\n")

        sni_tests = [
            ("ya.ru", "Яндекс"),
            ("google.com", "Google"),
            ("twitter.com", "Twitter"),
            ("youtube.com", "YouTube"),
            ("vk.com", "VK"),
        ]
        for sni, name in sni_tests:
            print(f"  SNI: {sni} ({name}): ", end="", flush=True)
            result = self.tls_handshake(SNI_TEST_IP, 443, sni=sni)
            if result == "ok":
                print(f"{GREEN}ПРОПУЩЕН ✓{NC}")
            elif result == "reset":
                print(f"{RED}ЗАБЛОКИРОВАН (RST) — ТСПУ РЕЖЕТ SNI!{NC}")
            else:
                print(f"{YELLOW}НЕТ ОТВЕТА{NC}")
        self.pause()

    def check_udp_ports(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[5] 📦 Проверка UDP-портов...{NC}\n")
        print(f"{CYAN}🎯 Цель: {self.server_ip}{NC}\n")

        print("  UDP 53 (DNS): ", end="", flush=True)
        dns_result = self.dns_query_a("ya.ru", self.server_ip, timeout=2)
        if dns_result:
            print(f"{GREEN}ОТВЕЧАЕТ ✓{NC}")
        else:
            print(f"{YELLOW}НЕТ ОТВЕТА (не DNS сервер){NC}")

        print("\n  UDP 443 (QUIC):")
        print("    → QUIC не отвечает на пустые UDP-пакеты")
        print("    → 'НЕТ ОТВЕТА' — ЭТО НОРМАЛЬНО")
        print("\n  UDP 8443 (Hysteria):")
        print("    → Hysteria использует свой UDP handshake")
        print("    → 'НЕТ ОТВЕТА' — ЭТО НОРМАЛЬНО")
        print("\n  UDP 51820 (WireGuard):")
        print("    → WireGuard игнорирует неавторизованные пакеты")
        print("    → 'НЕТ ОТВЕТА' — ЭТО НОРМАЛЬНО")
        print(f"\n{BLUE}💡 Пояснение:{NC}")
        print("  Только UDP 53 (DNS) гарантированно отвечает на пустые пакеты.")
        print(f"  {GREEN}'НЕТ ОТВЕТА' НЕ означает, что порт заблокирован!{NC}")
        self.pause()

    def check_dns(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[6] 🌐 Проверка внешних DNS-серверов...{NC}\n")

        dns_servers = [
            ("8.8.8.8", "Google DNS"),
            ("1.1.1.1", "Cloudflare DNS"),
            ("77.88.8.8", "Яндекс DNS"),
        ]
        for ip, name in dns_servers:
            print(f"  {name} ({ip}): ", end="", flush=True)
            result = self.dns_query_a("ya.ru", ip, timeout=3)
            if result:
                print(f"{GREEN}РАБОТАЕТ ✓{NC}")
            else:
                print(f"{RED}НЕ ДОСТУПЕН (таймаут){NC}")
        self.pause()

    def start_web_server(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[7] 🚀 Запуск временного веб-сервера на порту 443...{NC}\n")

        if sys.platform != "win32" and os.geteuid() != 0:
            print(f"{RED}❌ Ошибка: нужны права root (sudo){NC}")
            self.pause()
            return

        local_ip = self.get_local_ip() or "localhost"
        web_dir = Path(tempfile.mkdtemp(prefix="tspu_web_test_"))
        index = web_dir / "index.html"
        index.write_text(
            f"""<!DOCTYPE html>
<html><head><title>ТСПУ Тест</title></head>
<body><h1>✓ Веб-сервер работает!</h1>
<p>Время: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>Проверка: curl -k https://localhost:443</p>
</body></html>""",
            encoding="utf-8",
        )

        cert_path = web_dir / "cert.pem"
        key_path = web_dir / "key.pem"
        openssl = shutil.which("openssl")
        if not openssl:
            print(f"{RED}❌ openssl не найден в PATH{NC}")
            shutil.rmtree(web_dir, ignore_errors=True)
            self.pause()
            return

        subprocess.run(
            [
                openssl,
                "req", "-x509", "-newkey", "rsa:4096",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "1", "-nodes", "-subj", "/CN=localhost",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

        handler = lambda *args, **kwargs: http.server.SimpleHTTPRequestHandler(  # noqa: E731
            *args, directory=str(web_dir), **kwargs
        )
        httpd = http.server.HTTPServer(("0.0.0.0", 443), handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_path), str(key_path))
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

        self.clear_screen()
        self.print_header()
        print(f"{GREEN}✅ Веб-сервер запущен!{NC}\n")
        print(f"{CYAN}📡 Доступные адреса:{NC}")
        print("  • https://localhost:443")
        print(f"  • https://{local_ip}:443")
        print(f"\n{RED}⚠️  Для остановки нажмите Ctrl+C{NC}\n")

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
            shutil.rmtree(web_dir, ignore_errors=True)
            print(f"\n{GREEN}✅ Веб-сервер остановлен{NC}")
        self.pause()

    def check_server(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[8] 🖥️  Полная проверка сервера {self.server_ip}...{NC}\n")

        print("  Пинг: ", end="", flush=True)
        if self.ping_host(self.server_ip):
            print(f"{GREEN}ДОСТУПЕН ✓{NC}")
        else:
            print(f"{RED}НЕ ДОСТУПЕН ✗{NC}")

        print(f"\n{CYAN}🔌 TCP порты:{NC}")
        for port in (22, 80, 443, 8080, 8443):
            print(f"    Порт {port}: ", end="", flush=True)
            if self.check_port_tcp(self.server_ip, port):
                print(f"{GREEN}ОТКРЫТ ✓{NC}")
            else:
                print(f"{YELLOW}ЗАКРЫТ/ФИЛЬТР{NC}")
        self.pause()

    def check_ports_detailed(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[9] 📊 Детальный анализ портов{NC}\n")
        print(f"  {BLUE}Порт   Сервис        Статус{NC}")
        print(f"  {BLUE}----   ------        -------------{NC}")

        services = {
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            8080: "HTTP-alt",
            8443: "HTTPS-alt",
        }
        for port, service in services.items():
            print(f"  {port:<6} {service:<12} ", end="", flush=True)
            if self.check_port_tcp(self.server_ip, port):
                print(f"{GREEN}ОТКРЫТ ✓{NC}")
            else:
                print(f"{YELLOW}ЗАКРЫТ/ФИЛЬТР{NC}")
            time.sleep(0.1)
        self.pause()

    def check_my_ip(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[10] 🌍 Определение вашего IP...{NC}\n")

        local_ip = self.get_local_ip()
        if local_ip:
            print(f"  Внутренний IP: {GREEN}{local_ip}{NC}")
        else:
            print(f"  {YELLOW}Внутренний IP: не определяется{NC}")

        external_ip = self.get_external_ip()
        if external_ip:
            print(f"  Внешний IP:    {GREEN}{external_ip}{NC}")
        else:
            print(f"  {YELLOW}Внешний IP: не удалось определить{NC}")
        self.pause()

    def rkn_block_check(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[11] 🔬 Расширенная диагностика блокировок (4 слоя){NC}\n")

        print(f"{GREEN}--- Белый список (контрольная группа) ---{NC}")
        print(f"\n{CYAN}Проверка: Яндекс (ya.ru){NC}")
        sys_ip = self.dns_query_a("ya.ru")
        doh_ip = self.dns_query_a("ya.ru", "1.1.1.1")
        print("  DNS системный: ", end="")
        print(f"{GREEN}OK → {sys_ip[0]}{NC}" if sys_ip else f"{RED}НЕТ ОТВЕТА{NC}")
        print("  DNS DoH (1.1.1.1): ", end="")
        print(f"{GREEN}OK → {doh_ip[0]}{NC}" if doh_ip else f"{RED}НЕТ ОТВЕТА{NC}")
        print("  TCP порт 443: ", end="", flush=True)
        if self.check_port_tcp("ya.ru", 443):
            print(f"{GREEN}ОТКРЫТ{NC}")
        else:
            print(f"{RED}ЗАКРЫТ/ТАЙМАУТ{NC}")

        print(f"\n{RED}--- Чёрный список (заблокированные ресурсы) ---{NC}")
        print(f"\n{CYAN}Проверка: Twitter (twitter.com){NC}")
        sys_ip = self.dns_query_a("twitter.com")
        doh_ip = self.dns_query_a("twitter.com", "1.1.1.1")
        print("  DNS системный: ", end="")
        print(f"{GREEN}OK → {sys_ip[0]}{NC}" if sys_ip else f"{RED}НЕТ ОТВЕТА{NC}")
        print("  DNS DoH (1.1.1.1): ", end="")
        print(f"{GREEN}OK → {doh_ip[0]}{NC}" if doh_ip else f"{RED}НЕТ ОТВЕТА{NC}")

        tcp_ok = self.check_port_tcp("twitter.com", 443)
        print("  TCP порт 443: ", end="", flush=True)
        if tcp_ok:
            print(f"{GREEN}ОТКРЫТ{NC}")
        else:
            print(f"{RED}ЗАКРЫТ/ТАЙМАУТ{NC}")

        if tcp_ok:
            print("  TLS Handshake: ", end="", flush=True)
            tls = self.tls_handshake("twitter.com", 443, sni="twitter.com")
            if tls == "ok":
                print(f"{GREEN}УСПЕШНО{NC}")
            elif tls == "reset":
                print(f"{RED}СБРОШЕН (RST) — SNI-БЛОКИРОВКА ТСПУ!{NC}")
            else:
                print(f"{YELLOW}ТАЙМАУТ/ОШИБКА{NC}")
        self.pause()

    def check_split_dns(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[12] 🔍 Проверить Split DNS/утечку WebRTC{NC}\n")
        print(f"{CYAN}📌 ВНИМАНИЕ: Запустите этот тест ПРИ ВКЛЮЧЁННОМ VPN{NC}\n")
        answer = input("Нажмите Enter если VPN включён, или 'q' для выхода: ").strip().lower()
        if answer == "q":
            return

        print(f"\n{CYAN}[Проверка, какой IP видят сайты]:{NC}\n")
        ya_ip = self.https_remote_ip("ya.ru")
        print("  ya.ru видит IP: ", end="")
        print(f"{GREEN}{ya_ip}{NC}" if ya_ip else f"{YELLOW}не удалось определить{NC}")

        external_ip = self.get_external_ip()
        print("  ifconfig.me видит IP: ", end="")
        print(f"{GREEN}{external_ip}{NC}" if external_ip else f"{YELLOW}не удалось определить{NC}")

        print(f"\n{BLUE}📊 Анализ:{NC}")
        if ya_ip and external_ip and ya_ip != external_ip:
            print(f"  {GREEN}✅ Split DNS/туннелирование РАБОТАЕТ{NC}")
        elif ya_ip and external_ip and ya_ip == external_ip:
            print(f"  {RED}⚠️ ВОЗМОЖНА УТЕЧКА — оба сайта видят один IP{NC}")
        else:
            print(f"  {YELLOW}❓ Не удалось определить{NC}")
        self.pause()

    def udp_pair_test(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[13] 🧪 Тест UDP-связи между серверами (Hysteria/QUIC){NC}\n")
        print(f"{CYAN}Этот тест проверяет, блокирует ли провайдер UDP-трафик.{NC}")
        print("Для работы нужно запустить скрипт на ДВУХ серверах одновременно.\n")
        print(f"{GREEN}Выберите режим:{NC}")
        print(f"  {BLUE}1{NC}) Режим СЕРВЕР (приёмник) — запустить на сервере, который ЖДЁТ пакеты")
        print(f"  {BLUE}2{NC}) Режим КЛИЕНТ (отправитель) — запустить на сервере, который ОТПРАВЛЯЕТ")
        mode = input("\nВаш выбор: ").strip()

        if mode == "1":
            port_str = input("Введите порт для прослушивания (по умолчанию 9999): ").strip()
            port = int(port_str) if port_str else 9999
            print(f"\n{YELLOW}⚠️ Убедитесь, что порт {port} открыт в файрволе!{NC}")
            print(f"{YELLOW}⚠️ Если используется ufw: sudo ufw allow {port}/udp{NC}")
            print(f"{YELLOW}⚠️ На некоторых VPS нужно открыть порт в панели управления (Security Group){NC}\n")
            input(f"Нажмите Enter, чтобы начать прослушивание UDP порта {port}...")
            print(f"{GREEN}✅ Слушаю UDP порт {port}...{NC}")
            print(f"{CYAN}Ожидаю входящие пакеты. Для остановки нажмите Ctrl+C{NC}\n")

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", port))
            try:
                while True:
                    data, addr = sock.recvfrom(4096)
                    print(f"  Получено от {addr[0]}:{addr[1]}: {data.decode('utf-8', errors='replace')}")
            except KeyboardInterrupt:
                print(f"\n{YELLOW}⚠️ Прослушивание остановлено{NC}")
            finally:
                sock.close()

        elif mode == "2":
            target_ip = input("Введите IP адрес целевого сервера (приёмника): ").strip()
            if not target_ip:
                print(f"{RED}❌ IP адрес обязателен!{NC}")
                self.pause()
                return
            port_str = input("Введите порт целевого сервера (по умолчанию 9999): ").strip()
            port = int(port_str) if port_str else 9999
            message = input("Введите сообщение для отправки (по умолчанию 'TEST_UDP'): ").strip() or "TEST_UDP"
            count_str = input("Количество пакетов (по умолчанию 1): ").strip()
            count = int(count_str) if count_str else 1

            print(f"\n{CYAN}Отправляю {count} UDP пакет(ов) на {target_ip}:{port}{NC}\n")
            success = 0
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            for i in range(1, count + 1):
                payload = f"{message}_{i}".encode()
                print(f"  Пакет {i}: ", end="", flush=True)
                try:
                    sock.sendto(payload, (target_ip, port))
                    print(f"{GREEN}ОТПРАВЛЕН ✓{NC}")
                    success += 1
                except OSError:
                    print(f"{RED}ОШИБКА (нет ответа или таймаут){NC}")
                time.sleep(0.5)
            sock.close()

            print(f"\n{CYAN}📊 Результат:{NC}")
            if success == count:
                print(f"  {GREEN}✅ Все {success} пакетов отправлены.{NC}")
                print("     Если на сервере-приёмнике они появились — UDP РАБОТАЕТ.")
            elif success > 0:
                print(f"  {YELLOW}⚠️ Отправлено только {success} из {count} пакетов. Возможны проблемы с сетью.{NC}")
            else:
                print(f"  {RED}❌ Не удалось отправить ни одного пакета. Провайдер или хостинг блокирует UDP!{NC}")
        else:
            print(f"{RED}❌ Неверный выбор{NC}")
        self.pause()

    def check_nat_type(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[14] 🌐 Определение типа NAT (CGNAT/Full Cone/Symmetric){NC}\n")
        print(f"{CYAN}Этот тест помогает понять, почему не работают входящие соединения.{NC}\n")

        external_ip = self.get_external_ip()
        if not external_ip:
            print(f"{RED}❌ Не удалось определить внешний IP{NC}")
            self.pause()
            return

        print(f"  Внешний IP: {GREEN}{external_ip}{NC}")
        parts = external_ip.split(".")
        a, b = int(parts[0]), int(parts[1])
        if a == 100 and 64 <= b <= 127:
            print(f"  {RED}⚠️ Обнаружен CGNAT (адрес 100.64.0.0/10){NC}")
            print("     → Прямые входящие соединения невозможны")
            print("     → Используйте туннелирование (VPN, reverse proxy)")
        else:
            print(f"  {GREEN}✅ Публичный IP (не CGNAT){NC}")

        print(f"\n{CYAN}🔌 Проверка входящих соединений:{NC}")
        print("  Запустите на этом же компьютере:")
        print(f"    {YELLOW}python -c \"import socket;s=socket.socket();s.bind(('0.0.0.0',8888));s.listen();c,_=s.accept();print('OK')\"{NC}")
        print("  И попросите друга подключиться:")
        print(f"    {YELLOW}nc -zv {external_ip} 8888{NC}")
        print("\n  Если соединение не устанавливается — вы за CGNAT или порты закрыты оператором.")
        self.pause()

    # ===================================================================================================================================================
    # ====================================================================== 15 Тест скорости UDP канала ================================================
    # ===================================================================================================================================================
    def test_udp_speed(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[15] 📊 Тест скорости UDP канала{NC}\n")
        print(f"{CYAN}ВНИМАНИЕ: Этот тест приблизительный. Требуется сервер-приёмник.{NC}\n")

        target_ip = input("IP адрес сервера-приёмника: ").strip()
        if not target_ip:
            print(f"{RED}❌ IP адрес обязателен!{NC}")
            self.pause()
            return
        port_str = input("Порт (по умолчанию 9999): ").strip()
        port = int(port_str) if port_str else 9999

        print(f"\n{YELLOW}Отправляю 10 пакетов по 1KB...{NC}\n")
        payload = b"X" * 1024
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        total_time = 0
        for i in range(1, 11):
            start = time.perf_counter()
            try:
                sock.sendto(f"TEST_SPEED_{i}".encode() + payload[:32], (target_ip, port))
            except OSError:
                pass
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            print(f"  Пакет {i}: {elapsed_ms} мс")
            total_time += elapsed_ms
            time.sleep(0.5)
        sock.close()

        avg_time = total_time // 10
        print(f"\n{CYAN}📊 Средняя задержка: {avg_time} мс{NC}")
        if avg_time < 50:
            print(f"  {GREEN}✅ Отлично! UDP канал подходит для Hysteria/WireGuard{NC}")
        elif avg_time < 150:
            print(f"  {YELLOW}⚠️ Нормально, но возможны проблемы при высокой нагрузке{NC}")
        else:
            print(f"  {RED}❌ Высокая задержка! Hysteria/WireGuard будут работать медленно{NC}")
        self.pause()

    # ===================================================================================================================================================
    # ====================================================================== 16 Настройка REALITY / VPN (VLESS+TCP+REALITY) =============================
    # ===================================================================================================================================================
    def configure_reality(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[16] ⚙️  Настройка REALITY / VPN (VLESS+TCP+REALITY){NC}\n")
        print(f"{CYAN}Текущие параметры:{NC}")
        print(f"  IP сервера (VPS):  {GREEN}{self.server_ip}{NC}")
        print(f"  Порт:              {GREEN}{self.reality_port}{NC}")
        print(f"  SNI (serverNames): {GREEN}{self.reality_sni}{NC}\n")
        print(f"{BLUE}Популярные SNI для REALITY:{NC}")
        for i, preset in enumerate(REALITY_SNI_PRESETS, 1):
            print(f"  {i}) {preset}")
        print()

        new_ip = input(f"IP VPS [{self.server_ip}]: ").strip()
        if new_ip:
            if self.is_valid_ip(new_ip):
                self.server_ip = new_ip
            else:
                print(f"{RED}❌ Неверный IP{NC}")
                self.pause()
                return

        port_str = input(f"Порт [{self.reality_port}]: ").strip()
        if port_str:
            try:
                self.reality_port = int(port_str)
            except ValueError:
                print(f"{RED}❌ Неверный порт{NC}")
                self.pause()
                return

        sni_in = input(f"SNI dest [{self.reality_sni}] (номер пресета или домен): ").strip()
        if sni_in.isdigit() and 1 <= int(sni_in) <= len(REALITY_SNI_PRESETS):
            self.reality_sni = REALITY_SNI_PRESETS[int(sni_in) - 1]
        elif sni_in:
            self.reality_sni = sni_in

        self.save_config()
        print(f"\n{GREEN}✅ Сохранено: {self.server_ip}:{self.reality_port}, SNI={self.reality_sni}{NC}")
        self.pause()

    # ===================================================================================================================================================
    # ====================================================================== 17 TLS к VPN-серверу (OpenSSL) =============================================
    # ===================================================================================================================================================
    def test_vpn_tls(self) -> None:
        """TLS к VPN-серверу с SNI как в REALITY (OpenSSL-отпечаток)."""
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[17] 🔐 TLS рукопожатие к VPN (OpenSSL){NC}\n")
        print(f"{YELLOW}Для REALITY handshake_failure — норма: сервер отклоняет не-VLESS клиент.{NC}\n")

        targets = self.get_vpn_targets()
        if not targets:
            self.pause()
            return
        host, port, sni = targets
        if self.vpn_config_valid():
            print(f"{GREEN}✓ Используются сохранённые параметры:{NC} {host}:{port}, SNI={sni}\n")

        print(f"{CYAN}Проверка...{NC}\n")
        print("  TCP: ", end="", flush=True)
        if not self.check_port_tcp(host, port):
            print(f"{RED}НЕДОСТУПЕН{NC}")
            print(f"\n{RED}⚠️ До TLS не дошли — проверьте L3/белый список (п. 1, 3){NC}")
            self.pause()
            return
        print(f"{GREEN}OK{NC}")

        result = self.tls_probe_openssl(host, port, sni)
        self._print_probe("TLS (OpenSSL)", result)
        self._print_tls_interpretation(result, "OpenSSL", reality_vps=True)

        if result.alert_name == "handshake_failure" or result.status in ("alert", "error"):
            print(f"\n{CYAN}Дополнительно: сырой Client Hello (п. 18)...{NC}")
            raw = self.probe_raw_client_hello(host, port, sni, "chrome")
            self._print_probe("Client Hello (chrome)", raw)
            if raw.path_reachable:
                print(
                    f"\n  {GREEN}✅ Сервер отвечает на TLS — ТСПУ, скорее всего, не блокирует.{NC}\n"
                    f"     Если VPN падает с 'TLS handshake error' — проверьте:\n"
                    f"     • publicKey / privateKey REALITY\n"
                    f"     • shortId, serverNames (SNI)\n"
                    f"     • UUID VLESS, flow (xtls-rprx-vision)\n"
                    f"     • время на устройстве"
                )
            elif raw.status in ("reset", "timeout"):
                print(
                    f"\n  {RED}❌ Сырой CHLO тоже не проходит — возможна блокировка ТСПУ (п. 18, 19).{NC}"
                )
        self.pause()

    # ===================================================================================================================================================
    # ====================================================================== 18 Отправка Client Hello (сырой, Chrome-подобный) ==========================
    # ===================================================================================================================================================
    def test_raw_client_hello(self) -> None:
        """Сырой Client Hello (Chrome-подобный) — ближе к REALITY/uTLS."""
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[18] 📨 Отправка Client Hello (сырой, Chrome-подобный){NC}\n")

        targets = self.get_vpn_targets()
        if not targets:
            self.pause()
            return
        host, port, sni = targets
        if self.vpn_config_valid():
            print(f"{GREEN}✓ Используются сохранённые параметры:{NC} {host}:{port}, SNI={sni}\n")

        print(f"{BLUE}Профиль:{NC} 1) chrome  2) minimal")
        prof = input("Выбор [1]: ").strip()
        profile = "minimal" if prof == "2" else "chrome"

        print(f"\n{CYAN}Отправляю Client Hello ({profile}) → {host}:{port}, SNI={sni}{NC}\n")
        print("  TCP: ", end="", flush=True)
        if not self.check_port_tcp(host, port):
            print(f"{RED}НЕДОСТУПЕН{NC}")
            self.pause()
            return
        print(f"{GREEN}OK{NC}")

        result = self.probe_raw_client_hello(host, port, sni, profile)
        self._print_probe(f"Ответ на Client Hello ({profile})", result)
        self._print_tls_interpretation(result, profile)

        print(f"\n{CYAN}Сравнение с OpenSSL на том же хосте:{NC}")
        openssl_result = self.tls_probe_openssl(host, port, sni)
        self._print_probe("TLS (OpenSSL)", openssl_result)
        if result.status in ("reset", "timeout") and openssl_result.status == "ok":
            print(
                f"\n  {YELLOW}⚠️ OpenSSL проходит, сырой CHLO — нет: "
                f"ТСПУ режет по отпечатку TLS (JA3/JA4), не только SNI.{NC}"
            )
        elif result.status in ("server_hello", "ok") and openssl_result.status in ("reset", "timeout"):
            print(
                f"\n  {YELLOW}⚠️ Сырой CHLO проходит, OpenSSL — нет: "
                f"VPN-клиент с uTLS может работать лучше стандартного TLS.{NC}"
            )
        self.pause()

    # ===================================================================================================================================================
    def _print_tls_interpretation(
        self, result: TlsProbeResult, method: str, *, reality_vps: bool = False
    ) -> None:
        print(f"\n{BLUE}📊 Интерпретация ({method}):{NC}")
        if result.status in ("ok", "server_hello"):
            print(f"  {GREEN}✅ TLS-этап до ответа сервера пройден.{NC}")
            if reality_vps:
                print("     Полный TLS с обычным клиентом — VPS не REALITY или fallback на реальный сайт.")
            else:
                print("     Если VPN всё равно падает — проверьте ключи REALITY, shortId, UUID.")
        elif result.alert_name == "handshake_failure":
            print(
                f"  {GREEN}✅ Это нормально для REALITY!{NC} Сервер получил Client Hello и отклонил "
                "не-VLESS клиент."
            )
            print("     → Путь до VPS открыт, ТСПУ скорее всего не режет.")
            print("     → 'TLS handshake error' в VPN-клиенте — проверьте конфиг REALITY на сервере и в приложении.")
        elif result.status == "reset":
            print(f"  {RED}❌ RST после Client Hello — типичная блокировка ТСПУ (SNI/DPI).{NC}")
            print("     Попробуйте другой dest SNI (п. 16) или другой порт.")
        elif result.status == "timeout":
            print(f"  {YELLOW}⚠️ Таймаут — белый список L3, мёртвый VPS или фильтр без RST.{NC}")
        elif result.status == "alert":
            print(f"  {YELLOW}⚠️ TLS Alert ({result.alert_name}) — сервер ответил отказом.{NC}")
            if reality_vps:
                print("     Для REALITY-VPS это может быть ожидаемо; сверьте SNI с serverNames.")
        elif result.status == "error":
            print(f"  {YELLOW}⚠️ Ошибка TLS: {result.detail}{NC}")
        elif result.status == "tcp_fail":
            print(f"  {RED}❌ TCP не установлен — сеть или IP VPS недоступен.{NC}")

    # ===================================================================================================================================================
    # ====================================================================== 19 Полная диагностика VPN/REALITY ==========================================
    # ===================================================================================================================================================
    def test_reality_full(self) -> None:
        """Полная цепочка диагностики VPN/REALITY."""
        self.clear_screen()
        self.print_header()
        print(f"{YELLOW}[19] 🛡️  Полная диагностика VPN / REALITY{NC}\n")
        host = self.server_ip
        port = self.reality_port
        sni = self.reality_sni
        print(f"{CYAN}Параметры: {host}:{port}, SNI={sni}{NC}\n")

        # 1. Режим ТСПУ (кратко)
        print(f"{GREEN}── 1. Режим сети (Google IP) ──{NC}")
        icmp_ok = self.ping_host(BLOCKED_TEST_IP)
        tcp_google = self.check_port_tcp(BLOCKED_TEST_IP, 443)
        print(f"  ICMP Google: {'OK' if icmp_ok else 'нет'}")
        print(f"  TCP Google:443: {'OK' if tcp_google else 'нет'}")
        if icmp_ok and not tcp_google:
            print(f"  {YELLOW}→ Возможен режим белых списков (L3){NC}")
        print()

        # 2. TCP к VPS
        print(f"{GREEN}── 2. TCP к VPN-серверу ──{NC}")
        tcp_vps = self.check_port_tcp(host, port)
        print(f"  {host}:{port}: ", end="")
        print(f"{GREEN}ОТКРЫТ{NC}" if tcp_vps else f"{RED}ЗАКРЫТ/ТАЙМАУТ{NC}")
        if not tcp_vps:
            print(f"\n{RED}Дальнейшие TLS-тесты бессмысленны — нет TCP до VPS.{NC}")
            self.pause()
            return
        print()

        # 3. TLS OpenSSL к VPS
        print(f"{GREEN}── 3. TLS к VPS (OpenSSL, SNI={sni}) ──{NC}")
        r_ssl_vps = self.tls_probe_openssl(host, port, sni)
        self._print_probe("VPS OpenSSL", r_ssl_vps)
        print()

        # 4. Raw Client Hello к VPS
        print(f"{GREEN}── 4. Client Hello к VPS (Chrome) ──{NC}")
        r_raw_vps = self.probe_raw_client_hello(host, port, sni, "chrome")
        self._print_probe("VPS raw CHLO", r_raw_vps)
        print()

        # 5. SNI на эталонном IP (как п.4)
        print(f"{GREEN}── 5. SNI-фильтр на IP Яндекса ({SNI_TEST_IP}) ──{NC}")
        r_sni_ref = self.probe_raw_client_hello(SNI_TEST_IP, 443, sni, "chrome")
        self._print_probe(f"SNI {sni} @ Yandex IP", r_sni_ref)
        print()

        # 6. Сводка
        print(f"{BLUE}═══ Сводка ═══{NC}\n")
        vps_reachable = r_ssl_vps.path_reachable or r_raw_vps.path_reachable
        blocked_vps = not vps_reachable and (
            r_raw_vps.status in ("reset", "timeout")
            or r_ssl_vps.status in ("reset", "timeout")
        )
        blocked_sni = r_sni_ref.status in ("reset", "timeout") and not r_sni_ref.path_reachable
        reality_ok = (
            r_ssl_vps.alert_name == "handshake_failure"
            or r_raw_vps.alert_name == "handshake_failure"
        )
        fingerprint_mismatch = (
            r_raw_vps.path_reachable != r_ssl_vps.path_reachable
            and not reality_ok
        )

        if not tcp_vps:
            print(f"  {RED}● Нет TCP до VPS — блокировка L3 или сервер недоступен.{NC}")
        elif reality_ok or (vps_reachable and blocked_sni):
            print(f"  {GREEN}● Путь до VPS открыт (REALITY отклоняет чужой TLS — это норма).{NC}")
            print("     ТСПУ, скорее всего, не виноват. Проверьте конфиг VPN-клиента.")
        elif blocked_vps and blocked_sni:
            print(f"  {RED}● TLS режется и на VPS, и на эталонном IP — SNI '{sni}' в чёрном списке DPI.{NC}")
        elif blocked_vps and not blocked_sni:
            print(f"  {RED}● VPS недоступен по TLS, эталонный IP — OK — блокировка IP VPS или порта.{NC}")
        elif vps_reachable:
            print(f"  {GREEN}● TLS до VPS проходит — 'TLS handshake error' в клиенте скорее конфиг REALITY.{NC}")
        if fingerprint_mismatch:
            print(f"  {YELLOW}● Расхождение OpenSSL vs raw CHLO — важен отпечаток клиента (uTLS).{NC}")
        if icmp_ok and not tcp_google and not tcp_vps:
            print(f"  {YELLOW}● Белый список: ваш VPS, вероятно, не в разрешённых назначениях.{NC}")

        self.pause()

    # ------------------------------------------------------------------ menu

    def show_menu(self) -> None:
        self.clear_screen()
        self.print_header()
        print(f"{GREEN}Выберите действие:{NC}\n")
        print(f"  {BLUE}0{NC}) 🔧 Сменить IP сервера (сейчас: {self.server_ip})")
        print(f"  {BLUE}1{NC}) 🧪 Определить режим ТСПУ")
        print(f"  {BLUE}2{NC}) 📡 Проверить активность ТСПУ (curl)")
        print(f"  {BLUE}3{NC}) 🔍 Проверить доступность портов (TCP)")
        print(f"  {BLUE}4{NC}) 🎭 Проверить SNI-фильтрацию (L7)")
        print(f"  {BLUE}5{NC}) 📦 Проверить UDP-порты (пояснения)")
        print(f"  {BLUE}6{NC}) 🌐 Проверить внешние DNS")
        print(f"  {BLUE}7{NC}) 🚀 Запустить веб-сервер на 443")
        print(f"  {BLUE}8{NC}) 🖥️  Полная проверка сервера")
        print(f"  {BLUE}9{NC}) 📊 Детальный анализ портов")
        print(f"  {BLUE}10{NC}) 🌍 Определить ваш IP")
        print(f"  {BLUE}11{NC}) 🔬 Расширенная диагностика блокировок (4 слоя)")
        print(f"  {BLUE}12{NC}) 🔍 Проверить Split DNS/утечку")
        print(f"  {BLUE}13{NC}) 🧪 Тест UDP-связи между серверами (Hysteria/QUIC)")
        print(f"  {BLUE}14{NC}) 🌐 Определение типа NAT (CGNAT)")
        print(f"  {BLUE}15{NC}) 📊 Тест скорости UDP канала")
        print(f"  {BLUE}16{NC}) ⚙️  Настройка REALITY/VPN (SNI, порт)")
        print(f"  {BLUE}17{NC}) 🔐 TLS к VPN-серверу (OpenSSL)")
        print(f"  {BLUE}18{NC}) 📨 Client Hello сырой (Chrome, как uTLS)")
        print(f"  {BLUE}19{NC}) 🛡️  Полная диагностика VPN/REALITY")
        print(f"  {BLUE}q{NC}) ❌ Выход")
        print()

    def run(self) -> None:
        actions = {
            "0": self.configure_server_ip,
            "1": self.detect_tspu_mode,
            "2": self.check_tspu_active,
            "3": self.check_ports,
            "4": self.test_sni_filtering,
            "5": self.check_udp_ports,
            "6": self.check_dns,
            "7": self.start_web_server,
            "8": self.check_server,
            "9": self.check_ports_detailed,
            "10": self.check_my_ip,
            "11": self.rkn_block_check,
            "12": self.check_split_dns,
            "13": self.udp_pair_test,
            "14": self.check_nat_type,
            "15": self.test_udp_speed,
            "16": self.configure_reality,
            "17": self.test_vpn_tls,
            "18": self.test_raw_client_hello,
            "19": self.test_reality_full,
        }
        while True:
            self.show_menu()
            choice = input("Ваш выбор: ").strip()
            print()
            if choice.lower() == "q":
                self.clear_screen()
                print(f"{GREEN}До свидания!{NC}")
                break
            action = actions.get(choice)
            if action:
                action()
            else:
                print(f"{RED}Неверный выбор: '{choice}'{NC}")
                time.sleep(1)


def main() -> None:
    if sys.version_info < (3, 8):
        print("Требуется Python 3.8 или новее")
        sys.exit(1)
    TspuChecker().run()


if __name__ == "__main__":
    main()
