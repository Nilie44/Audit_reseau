# Audit_reseau
Ce projet me permet de mettre sur pied un système d'audit automatisé. Plusieurs logiciels ont été utilisés.
le fichier **dependences.sh** contient l'ensemble d'outil qui seront installer avant l'éxecution de notre script python. 
**Nmap** : A permit de faire une decouverte du réseau et resortir la liste des adresse ip des hôtes sur le réseau et les ports ouverts.  
**OpenVAS** : Grâce a ce logiciel, j'ai pu scanner hôtre après hôte les adresse ip present sur la liste generer par nmap pour resortir les vulnérabilités, les ports (services) associé, les CVEs associé, une proposition de solution et bien d'autres paramètres.     
**Wireshark** : une fois les services vulnerables detectées, j'utilise wireshark pour observer en temps réel le traffic sur ces services afin de voir si quelqu'un a déjà explioter cette vulnérabilité. 
Elle permet aussi de verifier l'intégrité des paquets pour voir s'il n'y a pas d'anomalies dans les entêtes (ipspoofing)    
**Snort** : En parallèle, notre logiciel snort  écoute le réseau pour se rassurer qu’un intrus  ne s’introduit pas dans le réseau.   
**Openscap** : De Plus on fera aussi un scan de conformité avec OpenSCAP-workbench mais peu pratique à grande échelle   
**Metasploite** :En dernière position, on fait du pentesting(metasploite) pour vérifier si le réseau n'est pas sensible aux autres types d’attaques(sql injection, attaque par force brute etc)

