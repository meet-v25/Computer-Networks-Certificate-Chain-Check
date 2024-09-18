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

        for k in reversed(list(range(len(cert_chain)))):
            
            cert = cert_chain[k]; 
            # print(f"\n\nCERT ({k}) -> IS_Expired? :", cert.has_expired(), "\n\n",); 
            # for i in range(cert.get_extension_count()): print(i,cert.get_extension(i).get_short_name().decode(),cert.get_extension(i),"\n"); 
            
            if(cert.has_expired()):                     # If any certificate is expired, we return False
                # print("\n [[[ LOC1 ]]] \n"); 
                validity = False; return validity; 

            # If SAN (Subject Alternative Name , subjectAltName) is valid, then so is certificate
            for i in range(cert.get_extension_count()):
                if(cert.get_extension(i).get_short_name()==b'subjectAltName'):
                    for name in cert.get_extension(i).get_data().split(b'\x82')[1:]:
                        if target_domain.encode('utf-8') in name.strip(): 
                            # print("\n [[[ LOC5 ]]] \n"); 
                            validity = True; break; 
            
            if(validity): continue; # Go to next certificate to verify

            # If CN (Common Name) is valid, then so is certificate
            common_name = cert.get_subject().commonName; common_name_list = str(common_name).split("."); 
            if(len(common_name_list)>1):
                common_name_only = common_name_list[1]; 
                # print("\n\n", common_name, target_domain, common_name_list, "\n\n"); 

                if(target_domain.encode('utf-8') in common_name.encode('utf-8')): 
                    # print("\n [[[ LOC8 ]]] \n"); 
                    validity = True; continue; 
                
                if(re.search(r"^(www\.)?" + common_name_only + r"\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$", target_domain)): 
                    # print("\n [[[ LOC9 ]]] \n"); 
                    validity = True; continue; 

            # Create a contextStore for the website, and store all valid certificates to verify the chain connections
            store_ctx = crypto.X509StoreContext(store,cert); 
            try: store_ctx.verify_certificate(); store.add_cert(cert); 
            except Exception as e: 
                print("X509StoreContext Storing Exception as below:\n", e); 
                validity = False; return validity; 


        # print("\n [[[ LOC-Final ]]] \n"); 
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
