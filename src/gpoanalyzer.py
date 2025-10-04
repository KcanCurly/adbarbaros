import argparse
from ldap3 import ALL, NTLM, Connection, Server, SUBTREE, Tls
from ldap3.core.exceptions import LDAPBindError
import ssl
import socket
import traceback

def create_ldap_server(server, use_ssl):
    if use_ssl:
        tls = Tls(validate=ssl.CERT_NONE)
        return Server(server, use_ssl=True, tls=tls, get_info=ALL)
    return Server(server, get_info=ALL)

def get_connection(server, domain, user, password):
    conn = None
    try:
        try:
            server = create_ldap_server(server, True)
            conn = Connection(
                server,
                user=f"{domain}\\{user}",
                password=password,
                authentication=NTLM,
                channel_binding="TLS_CHANNEL_BINDING",
                auto_bind=True,
                auto_range=True,
            )
            print("Connecting using ntlm - channel binding")
        except (ssl.SSLError, socket.error, LDAPBindError) as e:
            print("1", e)
            server = create_ldap_server(server, False)
            conn = Connection(
                server,
                user=f"{domain}\\{user}",
                password=password,
                authentication=NTLM,
                auto_bind=True,
                auto_range=True,
            )
            print("Connecting using ntlm")
    except Exception as e:
        print("2", e)
        traceback.print_exc() 
        return None
    return conn

def main():
    parser = argparse.ArgumentParser(description='AD Barbaros')
    parser.add_argument('--host', required=True, help='IP or hostname of the LDAP server')
    parser.add_argument('--domain', required=True, help='AD domain name (e.g., example.local)')
    parser.add_argument('--username', required=True, help='Username')
    parser.add_argument('--password', required=True, help='Password')
    args = parser.parse_args()

    conn = get_connection(args.host, args.domain, args.username, args.password)
    if not conn:
        print("LDAP connection failed")
        return
    
    conn.search(
        search_base='',
        search_filter='(objectClass=*)',
        search_scope='BASE',
        attributes=['*', '+']  # '+' gets operational attributes like schemaNamingContext
    )

    rootdse = conn.entries[0]

    schema_dn = rootdse.schemaNamingContext.value
    print(schema_dn)

    conn.search(
        search_base=schema_dn,
        search_filter='(objectClass=groupPolicyContainer)',
        attributes=['displayName', 'gPCFileSysPath', 'versionNumber']
    )

    gpos = []
    for entry in conn.entries:
        gpos.append({
            'name': entry.displayName.value,
            'path': entry.gPCFileSysPath.value,
            'version': entry.versionNumber.value
        })

    for gpo in gpos:
        print(gpo)
