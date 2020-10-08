# Include standard modules
import getopt, sys
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup

try:
    print("\nIncializando...")
    ip_address = "ERROR"
    time_out = 2
    retry_ = 1
    clients = []
    
    #SALVING ARGUMENTS
    argument_list = sys.argv[1:]
    if len(argument_list) == 0:
        print("Argumentos insuficientes.\n")
        sys.exit(1)
        
    #OPTIONS
    short_options = "hi:r:t:"
    long_options = ["help","ip_address=","retry=","timeout="]
    
    #ARGUMENT FILTERING
    try:
        arguments, values = getopt.getopt(argument_list, short_options, long_options)
    except getopt.error as err:
        # Output error, and return with an error code
        print ("Argumento inválido.")
        sys.exit(1)
    for arg, opt in arguments:
        if arg in ("-i", "--ip_address"):
            ip_address = opt
        elif arg in ("-r","--retry"):
            retry_ = int(opt)
        elif arg in ("-t","--timeout"):
            time_out = int(opt)
        elif arg in ("-h", "--help"):
            print("asdasdasd")

        else:
            print("Argumento inválido.")

    # create ARP packet
    arp = ARP(pdst=ip_address)
    
    # create the Ether broadcast packet
    # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    #INITIALIZING
    print("Analisando "+ ip_address + "...")
    
    result = srp(packet, timeout=time_out, verbose=0, retry=retry_)[0]
    
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    #PRINTING
    print(" " + "_"*53)
    print("|IP" + " "*17+"|MAC" + " "*18 +"|Hostname"+" "*4 + "|")
    print(" " + "-"*53)
    
    for client in clients:
        print(" {:16}    {}    {}".format(client['ip'], client['mac'],MacLookup().lookup(client['mac'])))
    print("\nSaindo...")
except KeyboardInterrupt:
    print("Progama finalizado pelo usuario.")
    print("Saindo...")
    sys.exit(1)
except:
    raise