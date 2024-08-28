# !/usr/bin/python3

# python -m unittest tests/basic_tests.py   ######### FOR TESTING #########

from OpenSSL import SSL,crypto
import socket, certifi, pem, fnmatch, urllib, re



# Cert Paths
TRUSTED_CERTS_PEM = certifi.where()

def get_cert_chain(target_domain):
    '''
    This function gets the certificate chain from the provided
    target domain. This will be a list of x509 certificate objects.
    '''
    # Set up a TLS Connection
    dst = (target_domain.encode('utf-8'), 443)
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    s = socket.create_connection(dst)
    s = SSL.Connection(ctx, s)
    s.set_connect_state()
    s.set_tlsext_host_name(dst[0])

    # Send HTTP Req (initiates TLS Connection)
    s.sendall('HEAD / HTTP/1.0\n\n'.encode('utf-8'))
    s.recv(16)
    
    # Get Cert Meta Data from TLS connection
    test_site_certs = s.get_peer_cert_chain()
    s.close()
    return test_site_certs



def x509_cert_chain_check(target_domain: str) -> bool:
    '''
    This function returns true if the target_domain provides a valid 
    x509cert and false in case it doesn't or if there's an error.
    '''
    try:

        # Add roots'certs to X509store object, which is certified globally
        store = crypto.X509Store(); certs = pem.parse_file(TRUSTED_CERTS_PEM); 
        for cert in certs: store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM,str(cert))); 
        
        cert_chain = get_cert_chain(target_domain);     # Using given function to get certificate chain
        validity = False;                               # To store validity of cert_chain
        if(not cert_chain): return validity;            # Always False if no certificate received


        # For each cert, check validity, and add it to the valid-cert-store object


        return validity; 

    except Exception as e: 
        print("Some Error Occurred As Below:\n",e); return False; 




if __name__ == "__main__":
    
    # Standalone running to help you test your program
    print("Certificate Validator...")
    target_domain = input("Enter TLS site to validate: ")
    # item = 1
    # target_domain = [0,"www.google.com","www.facebook.com","expired.badssl.com","wrong.host.badssl.com"][item]
    print("Certificate for {} verifed: {}".format(target_domain, x509_cert_chain_check(target_domain)))
