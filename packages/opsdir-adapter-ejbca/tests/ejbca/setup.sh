#!/bin/sh
# setup.sh: the live test's data in a fresh keyfactor/ejbca-ce container (docker exec -i <container> sh < setup.sh, with
# Profiles.java copied to /tmp first): a CA with CRL/OCSP/CA issuer URLs, a profile pair, three certificates (one
# revoked) and the inventory reader the README states, its certificate under /tmp/out/pem. Restart the container
# after it: EJBCA trusts the CAs of its role members' certificates only from its next start.
set -e
E=/opt/keyfactor/bin/ejbca.sh; J=/usr/lib/jvm/java-21-slim/bin
q() { "$@" >/tmp/setup.log 2>&1 || { tail -20 /tmp/setup.log; exit 1; }; }
for p in "REST Certificate Management" "REST Certificate Management V2"; do q $E config protocols enable --name "$p"; done
q $E ca init --caname "CIAM Issuing CA" --dn "CN=CIAM Issuing CA,O=CIAMstack Test" --tokenType soft --tokenPass null \
  --keyspec secp256r1 --keytype ECDSA -v 3650 --policy null -s SHA256WithECDSA
q $E ca editca --caname "CIAM Issuing CA" --field defaultCRLDistPoint --value http://pki.example.test/crl/ciam-issuing.crl
q $E ca editca --caname "CIAM Issuing CA" --field defaultOCSPServiceLocator --value http://ocsp.example.test/
q $E ca editca --caname "CIAM Issuing CA" --field certificateAiaDefaultCaIssuerUri --value http://pki.example.test/ca/ciam-issuing.cer
CA=$($E ca listcas 2>&1 | grep -A1 "CA Name: CIAM Issuing CA" | grep -o "Id: -*[0-9]*" | grep -o -- "-*[0-9]*")
CP=$(ls /opt/keyfactor/ejbca/dist/ejbca-ejb-cli/lib/*.jar | tr "\n" ":")
mkdir -p /tmp/profiles /tmp/classes
q $J/javac -proc:none -cp "$CP" -d /tmp/classes /tmp/Profiles.java
q $J/java -cp "$CP:/tmp/classes" Profiles /tmp/profiles "$CA"
q $E ca importprofiles -d /tmp/profiles --caname "CIAM Issuing CA"
issue() {   # issue <username> <cn> <ca> <cert profile> <ee profile> <dir>
  q $E ra addendentity --username "$1" --dn "CN=$2,O=CIAMstack Test" --altname "dNSName=$2" --caname "$3" --type 1 \
    --token PEM --password foo123 --certprofile "$4" --eeprofile "$5"
  q $E ra setclearpwd --username "$1" --password foo123
  q $E batch --username "$1" -dir "$6"
}
mkdir -p /tmp/out
issue idm.lab idm.lab "CIAM Issuing CA" ciam-tls ciam-servers /tmp/out
issue sso.lab sso.lab "CIAM Issuing CA" ciam-tls ciam-servers /tmp/out
issue old-sso.lab old-sso.lab "CIAM Issuing CA" ciam-tls ciam-servers /tmp/out
q $E ra revokeendentity --username old-sso.lab -r 1
# the inventory reader: a client certificate from ManagementCA, its role granted only what the README states
q $E ra addendentity --username reader --dn "CN=inventory-reader,O=CIAMstack Test" --caname ManagementCA --type 1 \
  --token PEM --password foo123 --certprofile ENDUSER --eeprofile EMPTY
q $E ra setclearpwd --username reader --password foo123
q $E batch --username reader -dir /tmp/out
q $E roles addrole --role "Inventory Reader"
q $E roles addrolemember --role "Inventory Reader" --caname ManagementCA --with CertificateAuthenticationToken:WITH_COMMONNAME --value inventory-reader
for r in /administrator/ "/ca/ManagementCA/" "/ca/CIAM Issuing CA/" /ca_functionality/view_certificate/ \
         /endentityprofilesrules/EMPTY/view_end_entity/ /endentityprofilesrules/ciam-servers/view_end_entity/; do
  q $E roles changerule --name "Inventory Reader" --rule "$r" --state ACCEPT
done
echo done
