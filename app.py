#!/usr/bin/env python3
"""CertScope — inspect TLS certificates for domains you administer."""
import argparse,datetime as dt,json,socket,ssl,sys
def inspect(host,port,timeout):
 ctx=ssl.create_default_context()
 with socket.create_connection((host,port),timeout=timeout) as raw:
  with ctx.wrap_socket(raw,server_hostname=host) as s:
   cert=s.getpeercert(); der=s.getpeercert(binary_form=True)
 def name(parts):
  return ", ".join(f"{k}={v}" for group in parts for k,v in group)
 expires=dt.datetime.strptime(cert["notAfter"],"%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
 now=dt.datetime.now(dt.timezone.utc); days=(expires-now).total_seconds()/86400
 return {"host":host,"port":port,"protocol":"TLS","subject":name(cert.get("subject",[])),"issuer":name(cert.get("issuer",[])),"not_before":cert.get("notBefore"),"expires_utc":expires.isoformat(),"days_remaining":round(days,1),"expired":days<0,"serial_number":cert.get("serialNumber"),"subject_alt_names":[v for k,v in cert.get("subjectAltName",[]) if k=="DNS"],"sha256_der":__import__("hashlib").sha256(der).hexdigest()}
def main():
 p=argparse.ArgumentParser(description="Inspect TLS certificate validity and identity"); p.add_argument("hosts",nargs="+",help="hostname (optionally host:port)"); p.add_argument("--port",type=int,default=443); p.add_argument("--timeout",type=float,default=6); p.add_argument("--json",action="store_true"); a=p.parse_args()
 results=[]
 for item in a.hosts:
  host=item; port=a.port
  if item.count(":")==1:
   h,maybe=item.rsplit(":",1)
   if maybe.isdigit(): host=h; port=int(maybe)
  try: results.append(inspect(host,port,a.timeout))
  except Exception as e: results.append({"host":host,"port":port,"error":str(e)})
 if a.json: print(json.dumps(results,indent=2,ensure_ascii=False))
 else:
  for x in results:
   print("\n"+x["host"]+":"+str(x["port"]))
   if "error" in x: print("  ERROR:",x["error"]); continue
   status="EXPIRED" if x["expired"] else ("EXPIRING SOON" if x["days_remaining"]<30 else "VALID")
   print(f"  Status: {status} — {x['days_remaining']} days remaining")
   print("  Expires:",x["expires_utc"]); print("  Issuer:",x["issuer"]); print("  Subject:",x["subject"])
   print("  SHA-256:",x["sha256_der"])
 if any("error" in x or x.get("expired") for x in results): return 1
 return 0
if __name__=="__main__": sys.exit(main())
