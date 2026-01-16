import email,re,string,ipaddress
from bs4 import BeautifulSoup
from email.utils import getaddresses
from urllib.parse import urlparse
print("enter email and wirte END at the end of the email")
lines=[]
while True:
        line=input()
        if line == 'END':
           break
        lines.append(line)
x_email="\n".join(lines)
msg=email.message_from_string(x_email)

def html_to_text(html):
    soup = BeautifulSoup(html, "html.parser")
    return soup.get_text()
    
 
urgency_phrase=[
     "urgent",
    "immediately",
    "asap",
    "right now",
    "respond immediately",
    "quick response",
    "within 24 hours",
    "limited time",
    "Promptly",
    "without delay"
]
verification_phrases=[
      "immediate verification is required",
      "verification",
      "verify",
      "action required",
      "act now"
]
suspicious_domain_words = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "support",
    "billing",
    "payment",
    "confirm",
    "admin",
    "portal",
    "service",
    "auth"
]
negations=[
     "no",
     "not",
     "never",
     "without",
     "do not",
     "does not",
     "is not",
     "are not",
     "not required",
     "no need"

]
suspicious_tlds = [
    "ru", "su",
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "click", "link",
    "work", "support", "info",
    "online", "site", "live"
]


# for headers 
name_mail=msg['From']   #name and mail
date=msg['Date']         
subject=msg['subject']
cc_raw=msg['Cc']
bcc_raw=msg['Bcc']
to_reply=msg['Reply-to']
#for body
def ext_body():
      bodies =[]
      if not msg.is_multipart():
         if msg.get_content_type() =='text/plain':
          return msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8') 
         elif msg.get_content_type() == 'text/html':
           return html_to_text(msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8'))
      for part in msg.walk():
                content_type = part.get_content_type()
                content_deposition =str(part.get("Content-Disposition"))
                if 'attachment' in content_deposition:
                    continue
                if content_type == 'text/plain':
                  bodies.append(part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8'))
                elif content_type == 'text/html':
                  bodies.append(html_to_text(part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')))          
      return "\n".join(bodies)
#yaha pe dekhna zaroor hai ke agar true ata hai to print hoga warna nai hoga 

body=ext_body() 
norm_body=body.lower()
norm_body=re.sub(r"[!?-]+","",norm_body)

cc_list = getaddresses([cc_raw]) if cc_raw else []
cc_count = len(cc_list)

def calc(phrases):
    words=norm_body.split()
    count = 0
    for i,word in enumerate(words):
         one_word=word.strip(string.punctuation)
         two_words= " ".join([w.strip(string.punctuation) for w in words[i:i+2]])#punctutation hateyega 
         if one_word in phrases or two_words in phrases: 
           back=max(0, i-3)
           forward=min(len(words)-1, i+3)
           found_neg = False
           for j in range(back,forward+1):
                  if words[j] in negations or " ".join(words[j:j+2]) in negations:
                       found_neg=True
                       break
           if not found_neg:
               count +=1
    return count


urgency_found=calc(urgency_phrase)
verification_found=calc(verification_phrases)


def visible_urls(body):
    urls_pattern = r'https?://[^\s,]+'
    urls = re.findall(urls_pattern,body)
    return urls


def html_urls():
    url=[]
    url.extend(visible_urls(body))
    for parts in msg.walk():
      if parts.get_content_type() == 'text/html':
          html_body=parts.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8')
      else:
         html_body=''    
    soup = BeautifulSoup(html_body,"html.parser") 
    for a in soup.find_all("a",href=True):
        url.append(a['href'])
    return url

raw_urls=html_urls()

def is_ip_address(netloc):
    try:
         ipaddress.ip_address(netloc)
         return True
    except ValueError:
          return False

def check_ip(urls):
    ip=[]
    non_ip=[]
    for url in urls:
        parsed_url=urlparse(url)
        netloc=parsed_url.netloc
        netloc=netloc.lower()
        split_1=netloc.split("@")
        split_2=split_1[-1].split(":")
        clean_netloc=split_2[0]
        if is_ip_address(clean_netloc):
            ip.append(clean_netloc)
        else:
            non_ip.append(clean_netloc)
    return ip,non_ip

ip , domain = check_ip(raw_urls)

def urls_tlds(urls):
    tlds = []
    for url in urls:
         parsed_url=urlparse(url)
         netloc=parsed_url.netloc
         netloc=netloc.lower()
         split_1=netloc.split("@")
         split_2=split_1[-1].split(":")
         split_3=split_2[0].split(".")
         tld=split_3[-1]
         tlds.append(tld)
    return tlds

def urls_calc(urls):
    risk=0
    for url in urls:
        new_url=urlparse(url)
        if new_url.scheme == 'http':
            risk += 1
        if '.' not in new_url.netloc:
            risk +=1
        netloc=new_url.netloc
        netloc=netloc.lower()
        split_1=netloc.split("@")
        split_2=split_1[-1].split(":")
        split_3=split_2[0]
        if split_3 in ip:
            risk += 1
        if len(split_3.split('.')) >= 3:
            risk +=1
        if url.count('-') > 3:
            risk += 1 
    if risk >= 10:
        return 10
    elif risk >= 20:
        return 20
    else:
        return 0

def tld_calc(z):
  for tld in urls_tlds(z):
      if tld in suspicious_tlds:
          return True
      else:
          continue

url_return_val=urls_calc(domain)
final_risk=0
if name_mail != to_reply:
    final_risk += 10
if cc_count > 5:
    final_risk += 10
if tld_calc(domain):
    final_risk += 10
if len(ip) > 1 :
      final_risk += 20
if urgency_found > 5 :
    final_risk += 20
if verification_found > 5:
    final_risk += 20
url_calc_val=urls_calc(domain)
final_risk += url_return_val


print("this email has risk percentage of :" ,final_risk)