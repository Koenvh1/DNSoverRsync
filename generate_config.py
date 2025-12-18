record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "PTR"]

for t in record_types:
    print(f"""[{t}]
path = /tmp/dnsfs/{t}
comment = The location for all the {t} records
read only = yes
""")

for t in record_types:
    print(f"fusermount -uz /tmp/dnsfs/{t}")