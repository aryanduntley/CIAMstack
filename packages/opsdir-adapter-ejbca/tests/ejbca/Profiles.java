import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import java.beans.XMLEncoder;
import java.io.FileOutputStream;
import java.util.*;
// Profiles <dir> <ca id>: a certificate profile ciam-tls (id 1001: TLS server+client, 397 days, the CA's own
// CRL/OCSP/CA issuer URLs, only that CA) and an end entity profile ciam-servers (id 2001) for it, as EJBCA's export
// files, for ejbca.sh ca importprofiles.
public class Profiles {
  static void save(Object data, String path) throws Exception {
    try (XMLEncoder e = new XMLEncoder(new FileOutputStream(path))) { e.writeObject(data); }
  }
  public static void main(String[] a) throws Exception {
    int ca = Integer.parseInt(a[1]);
    CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SERVER);
    cp.setEncodedValidity("397d");
    cp.setAvailableCAs(new ArrayList<>(Arrays.asList(ca)));
    cp.setUseExtendedKeyUsage(true);
    cp.setExtendedKeyUsageOids(new ArrayList<>(Arrays.asList("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2")));
    cp.setUseCRLDistributionPoint(true);
    cp.setUseDefaultCRLDistributionPoint(true);
    cp.setUseAuthorityInformationAccess(true);
    cp.setUseDefaultOCSPServiceLocator(true);
    cp.setUseDefaultCAIssuer(true);
    save(cp.saveData(), a[0] + "/certprofile_ciam-tls-1001.xml");
    EndEntityProfile ep = new EndEntityProfile(true);
    ep.setAvailableCertificateProfileIds(new ArrayList<>(Arrays.asList(1001)));
    ep.setDefaultCertificateProfile(1001);
    ep.setAvailableCAs(new ArrayList<>(Arrays.asList(ca)));
    ep.setDefaultCA(ca);
    ep.addField("DNSNAME");
    save(ep.saveData(), a[0] + "/entityprofile_ciam-servers-2001.xml");
  }
}
